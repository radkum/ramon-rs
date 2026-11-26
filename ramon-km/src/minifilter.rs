//! Minifilter registration, the communication port and the unload callback.
//!
//! IRQL: `RamonUnload` and the port callbacks run at PASSIVE_LEVEL; the file callbacks it
//! dispatches are described in `minifilter/file_monitor.rs`. `RamonUnload` unregisters the
//! notify callbacks and stops the sender thread before the filter and its state are freed.
use alloc::boxed::Box;
use core::{
    mem,
    mem::size_of,
    ptr::null_mut,
    sync::atomic::{AtomicUsize, Ordering},
};

mod file_monitor;
use common::{
    command,
    constants::{COMM_PORT_NAME, FLT_PORT_ALL_ACCESS},
    handshake,
};
use file_monitor::FileMonitor;
use kernel_macros::{HandleToU32, NT_SUCCESS, PAGED_CODE};
use km_api_sys::{flt_kernel::*, ntddk::PsGetCurrentProcessId, ntifs::PsGetCurrentProcess};
use winapi::{
    km::wdm::{DEVICE_TYPE, PDRIVER_OBJECT, PEPROCESS},
    shared::{
        ntdef::{
            InitializeObjectAttributes, NTSTATUS, OBJECT_ATTRIBUTES, OBJ_CASE_INSENSITIVE,
            OBJ_KERNEL_HANDLE, POBJECT_ATTRIBUTES, PUCHAR, PULONG, PVOID, ULONG, USHORT,
        },
        ntstatus::{
            STATUS_ACCESS_DENIED, STATUS_INSUFFICIENT_RESOURCES, STATUS_INVALID_PARAMETER,
            STATUS_NOT_FOUND, STATUS_SUCCESS,
        },
    },
    um::winnt::PSECURITY_DESCRIPTOR,
};

// FltCloseClientPort's real ABI takes a pointer to the handle and writes NULL through it. The
// km-api-sys binding declares it as `&PFLT_PORT` (a shared reference to an out-parameter), the same
// class of bug that broke the registry cookie; declare it correctly here.
extern "system" {
    fn FltCloseClientPort(Filter: PFLT_FILTER, ClientPort: *mut PFLT_PORT);
    fn PsGetProcessImageFileName(process: PEPROCESS) -> *const u8;
}

// EPROCESS.ImageFileName is 15 bytes and not NUL-terminated when full.
const IMAGE_FILE_NAME_LEN: usize = 15;
// "ramon-client.exe" is 16 bytes, so the 15-byte image name is "ramon-client.ex".
const CLIENT_IMAGE_PREFIX: &[u8] = b"ramon-client";
// fltKernel.h; a mandatory unload proceeds even if the callback returns an error
const FLTFL_FILTER_UNLOAD_MANDATORY: u32 = 0x0000_0001;

use crate::{
    locked::Locked,
    notifiers::{adopt, adopt_tag, MmCopyMemory, MM_COPY_MEMORY_VIRTUAL},
    unicode_string,
};

#[allow(clippy::upper_case_acronyms)]
pub(crate) type PMINIFILTER = *mut Minifilter;
pub(crate) static S_MINIFILTER: Locked<Option<Box<Minifilter>>> = Locked::new(None);
static INSTANCE_NUMBER: AtomicUsize = AtomicUsize::new(0);
// the nonce of the last accepted handshake, so a captured connect context cannot be replayed
static LAST_NONCE: Locked<[u8; handshake::NONCE_LEN]> = Locked::new([0u8; handshake::NONCE_LEN]);

/// Initializes the slot before the sender thread exists: `deliver` may run while the notify
/// callbacks registered in `DriverEntry` are already producing events, and a zeroed FAST_MUTEX
/// is "locked" (bugcheck 0xA on the first acquire).
pub(crate) unsafe fn init() {
    S_MINIFILTER.init();
    LAST_NONCE.init();
}

pub(crate) struct Minifilter {
    pub filter_handle: PFLT_FILTER,
    server_port: PFLT_PORT,
    // set by on_connect, cleared by on_disconnect; atomic so `deliver` never reads a torn handle
    client_port: AtomicUsize,
    //on_command: FN,
    //context: PVOID
}

impl Minifilter {
    fn new_empty() -> Minifilter {
        Self {
            filter_handle: null_mut(),
            server_port: null_mut(),
            client_port: AtomicUsize::new(0),
        }
    }

    pub(crate) fn create(driver: PDRIVER_OBJECT) -> NTSTATUS {
        unsafe {
            log::info!("Minifilter::factory");
            let mut minifilter = match Box::try_new(Minifilter::new_empty()) {
                Ok(minifilter) => minifilter,
                Err(_) => return STATUS_INSUFFICIENT_RESOURCES,
            };
            // do not publish the box until init succeeds: the sender can be in `deliver`, and this
            // path frees the box after a failed init. The heap address stays stable when the Box is
            // moved into the slot, so the communication-port cookie set by init stays valid.
            let status = minifilter.init(driver);
            if NT_SUCCESS!(status) {
                *S_MINIFILTER.lock() = Some(minifilter);
            } else {
                log::info!("failed to init minifilter. Status: 0x{:08x}", status);
                // drop outside the lock: Minifilter::drop calls FltUnregisterFilter
                drop(minifilter);
            }
            status
        }
    }

    pub(crate) unsafe fn init(&mut self, driver: PDRIVER_OBJECT) -> NTSTATUS {
        log::info!("Minifilter::init");
        #[allow(unused_assignments)]
        let mut status = STATUS_SUCCESS;

        //--------------------FILTER_HANDLE-----------------------
        status = FltRegisterFilter(driver, &FILTER_REGISTRATION, &mut self.filter_handle);
        if !NT_SUCCESS!(status) {
            log::info!("failed to register filter 0x{:08x}", status);
            return status;
        }

        status = self.init_comm_channel();
        if !NT_SUCCESS!(status) {
            log::info!("failed to initialize comm channel 0x{:08x}", status);
            return status;
        }

        status = FltStartFiltering(self.filter_handle);
        if !NT_SUCCESS!(status) {
            log::info!("failed to start filtering 0x{:08x}", status);
            return status;
        }

        //cleaninng is done in destructor
        status
    }

    //comm functions
    /// Snapshot of the connected client port; `deliver` must not keep reading a field that
    /// `on_disconnect` may clear and close concurrently.
    pub(crate) fn client_port(&self) -> PFLT_PORT {
        self.client_port.load(Ordering::Acquire) as PFLT_PORT
    }

    //comm callbacks
    pub(crate) unsafe extern "system" fn on_connect(
        client_port: PFLT_PORT,
        server_port_cookie: PVOID,
        connection_context: PVOID,
        size_of_context: ULONG,
        connection_port_cookie: PPVOID,
    ) -> NTSTATUS {
        log::info!("Client Port connected");
        if server_port_cookie.is_null() {
            log::warn!("server_port_cookie is null");
            return STATUS_INVALID_PARAMETER;
        }

        // on_connect runs in the connecting client's context. Only the elevated sensor client may
        // drive the port; the default port ACL alone is not an application-level check.
        let process = PsGetCurrentProcess();
        let image = PsGetProcessImageFileName(process);
        let is_client = !image.is_null()
            && core::slice::from_raw_parts(image, IMAGE_FILE_NAME_LEN)
                .starts_with(CLIENT_IMAGE_PREFIX);
        let privileged = crate::guardrail::is_privileged();
        if !is_client || !privileged {
            let name = if image.is_null() {
                "<null>"
            } else {
                core::str::from_utf8(core::slice::from_raw_parts(image, IMAGE_FILE_NAME_LEN))
                    .unwrap_or("<non-ascii>")
            };
            log::warn!(
                "client port: rejected pid {} image {:?} privileged {}",
                HandleToU32!(PsGetCurrentProcessId()),
                name,
                privileged
            );
            return STATUS_ACCESS_DENIED;
        }

        // Cryptographic boundary: the connect context carries nonce || HMAC-SHA256(key, nonce).
        // The name/privilege checks above are spoofable; this one requires the shared key.
        let mut proof = [0u8; handshake::PROOF_LEN];
        let mut copied = 0usize;
        if size_of_context as usize != handshake::PROOF_LEN
            || connection_context.is_null()
            || !NT_SUCCESS!(MmCopyMemory(
                proof.as_mut_ptr() as PVOID,
                connection_context,
                handshake::PROOF_LEN,
                MM_COPY_MEMORY_VIRTUAL,
                &mut copied,
            ))
            || copied != handshake::PROOF_LEN
            || !handshake::verify_proof(handshake::port_key(), &proof)
        {
            log::warn!(
                "client port: rejected pid {} (bad handshake proof)",
                HandleToU32!(PsGetCurrentProcessId())
            );
            return STATUS_ACCESS_DENIED;
        }

        // a proof accepted once must not be accepted again: reject a replayed connect context
        {
            let nonce = handshake::proof_nonce(&proof);
            let mut last = LAST_NONCE.lock();
            if *last == *nonce {
                log::warn!("client port: replayed handshake nonce");
                return STATUS_ACCESS_DENIED;
            }
            last.copy_from_slice(nonce);
        }

        let minifilter = server_port_cookie as PMINIFILTER;
        // check-and-store as one atomic: two concurrent connects must not both win
        if (*minifilter)
            .client_port
            .compare_exchange(0, client_port as usize, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            log::warn!("client port: a client is already connected");
            return STATUS_ACCESS_DENIED;
        }

        // remember the client pid so MOTA ignores its own opens
        crate::mota::set_client_pid(HandleToU32!(PsGetCurrentProcessId()));

        *connection_port_cookie = server_port_cookie;

        STATUS_SUCCESS
    }

    pub(crate) unsafe extern "system" fn on_disconnect(connection_cookie: PVOID) {
        log::info!("Client Port disconnected");
        if connection_cookie.is_null() {
            return;
        }

        let l_this = connection_cookie as PMINIFILTER;

        // the old client pid must not stay exempt from MOTA after the client is gone
        crate::mota::set_client_pid(0);
        let mut port = (*l_this).client_port.swap(0, Ordering::AcqRel) as PFLT_PORT;
        if !port.is_null() {
            FltCloseClientPort((*l_this).filter_handle, &mut port as *mut PFLT_PORT);
        }
    }

    pub(crate) unsafe extern "system" fn on_command(
        port_cookie: PVOID,
        p_in: PVOID,
        in_size: ULONG,
        p_out: PVOID,
        out_size: ULONG,
        out_return: PULONG,
    ) -> NTSTATUS {
        *out_return = 0;

        if !port_cookie.is_null() && in_size as usize >= size_of::<ULONG>() {
            let _minifilter = port_cookie as PMINIFILTER;

            //if !minifilter.on_command.is_null() {
            //unsafe {
            // we should use method with object to store info, but for know we use static fn
            //return (*minifilter).on_command((*minifilter).context, p_in, in_size, p_out, out_size, out_return);
            return Minifilter::handle_command(
                p_in as PUCHAR,
                in_size,
                p_out as PUCHAR,
                out_size,
                out_return,
            );
            //}
            //}
        }

        STATUS_SUCCESS
    }

    unsafe fn init_comm_channel(&mut self /*context: PVOID, CB_on_command */) -> NTSTATUS {
        let mut port_security: PSECURITY_DESCRIPTOR = null_mut();
        let mut port_name = unicode_string(COMM_PORT_NAME);
        let mut oa: OBJECT_ATTRIBUTES = unsafe { mem::zeroed() };

        #[allow(unused_assignments)]
        let mut status = STATUS_SUCCESS;
        'comm: {
            status = FltBuildDefaultSecurityDescriptor(&mut port_security, FLT_PORT_ALL_ACCESS);
            if !NT_SUCCESS!(status) {
                log::warn!("failed to build security descriptor. Status: {}", status);
                break 'comm;
            }

            InitializeObjectAttributes(
                &mut oa as POBJECT_ATTRIBUTES,
                port_name.as_mut_ptr(),
                OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                null_mut(),
                port_security as PVOID,
            );
            let p_ramon = self as *const Minifilter as CONST_PVOID;
            status = FltCreateCommunicationPort(
                self.filter_handle,
                &mut self.server_port,
                &mut oa as POBJECT_ATTRIBUTES,
                p_ramon,
                Some(Minifilter::on_connect),
                Some(Minifilter::on_disconnect),
                Some(Minifilter::on_command),
                1,
            );
            if !NT_SUCCESS!(status) {
                log::warn!("failed to create comm port. Status: {}", status);
                break 'comm;
            }

            log::info!("SUCCESS to create comm port. Port name: {}", port_name);
            log::info!("SUCCESS to create comm port. Port name (degug): {:?}", port_name);
            break 'comm;
        }
        //cleanup
        if !port_security.is_null() {
            FltFreeSecurityDescriptor(port_security);
        }
        status
    }

    unsafe fn close_comm(&mut self) {
        log::info!("close_comm START");
        if !self.server_port.is_null() {
            FltCloseCommunicationPort(self.server_port);
            self.server_port = null_mut();
        }
        log::info!("close_comm FINISH");
    }

    fn handle_command(
        p_in: PUCHAR,
        in_size: ULONG,
        _p_out: PUCHAR,
        _out_size: ULONG,
        _out_return: PULONG,
    ) -> NTSTATUS {
        let len = in_size as usize;
        // every command body shares one stack buffer, sized to the largest configured body
        let mut cmd = [0u8; command::COMMAND_MAX];
        let mut copied = 0;
        // p_in is the client's user buffer: MmCopyMemory fails instead of faulting
        if len > cmd.len()
            || !NT_SUCCESS!(unsafe {
                MmCopyMemory(
                    cmd.as_mut_ptr() as PVOID,
                    p_in as PVOID,
                    len,
                    MM_COPY_MEMORY_VIRTUAL,
                    &mut copied,
                )
            })
            || copied != len
        {
            return STATUS_INVALID_PARAMETER;
        }
        let cmd = &cmd[..len];
        if let Some((tagged, any)) = command::guardrail_from_bytes(cmd) {
            unsafe {
                crate::guardrail::set(
                    command::guardrail_fragments(tagged),
                    command::guardrail_fragments(any),
                );
            }
            return STATUS_SUCCESS;
        }
        if let Some((patterns, suffix)) = command::mirage_from_bytes(cmd) {
            unsafe {
                crate::mirage::set(command::mirage_fragments(patterns), suffix);
            }
            return STATUS_SUCCESS;
        }
        if let Some((paths, sessions)) = command::mirage_except_from_bytes(cmd) {
            unsafe {
                crate::mirage::set_exceptions(
                    command::mirage_fragments(paths),
                    command::mirage_fragments(sessions),
                );
            }
            return STATUS_SUCCESS;
        }
        if let Some((child, tag)) = command::adopt_tag_from_bytes(cmd) {
            return if unsafe { adopt_tag(child, tag) } {
                STATUS_SUCCESS
            } else {
                STATUS_NOT_FOUND
            };
        }
        if let Some((file_id, session, path)) = command::mota_add_from_bytes(cmd) {
            crate::mota::load_entry(file_id, session, path);
            return STATUS_SUCCESS;
        }
        match command::adopt_from_bytes(cmd) {
            Some((child, causal)) if unsafe { adopt(child, causal) } => STATUS_SUCCESS,
            Some(_) => STATUS_NOT_FOUND,
            None => STATUS_INVALID_PARAMETER,
        }
    }
}

impl Drop for Minifilter {
    fn drop(&mut self) {
        log::info!("Minifilter::destructor");

        if !self.server_port.is_null() {
            unsafe {
                self.close_comm();
            }
        }

        if !self.filter_handle.is_null() {
            log::info!("FltUnregisterFilter before");
            unsafe {
                FltUnregisterFilter(self.filter_handle);
            }
            log::info!("FltUnregisterFilter success");
            self.filter_handle = null_mut();
        }

        log::info!("Minifilter::destructor FINISH");
    }
}

/*************************************************************************
    MiniFilter initialization and unload routines.
*************************************************************************/

const CALLBACKS: &[FLT_OPERATION_REGISTRATION] = {
    const IRP_MJ_WRITE: u8 = 0x04;
    // FltMgr operations (fltKernel.h): (UCHAR)-1 / (UCHAR)-2
    const IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION: u8 = 0xff;
    const IRP_MJ_RELEASE_FOR_SECTION_SYNCHRONIZATION: u8 = 0xfe;
    &[
        FLT_OPERATION_REGISTRATION::new()
            .set_major_function(FLT_OPERATION_REGISTRATION::IRP_MJ_CREATE)
            .set_preop(FileMonitor::RamonPreCreate)
            .set_postop(FileMonitor::RamonPostCreate),
        FLT_OPERATION_REGISTRATION::new()
            .set_major_function(IRP_MJ_WRITE)
            .set_postop(FileMonitor::RamonPostWrite),
        FLT_OPERATION_REGISTRATION::new()
            .set_major_function(FLT_OPERATION_REGISTRATION::IRP_MJ_SET_INFORMATION)
            .set_preop(FileMonitor::RamonPreSetInformation),
        FLT_OPERATION_REGISTRATION::new()
            .set_major_function(IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION)
            .set_preop(FileMonitor::RamonPreAcquireForSectionSync),
        FLT_OPERATION_REGISTRATION::new()
            .set_major_function(IRP_MJ_RELEASE_FOR_SECTION_SYNCHRONIZATION)
            .set_preop(FileMonitor::RamonPreReleaseForSectionSync),
        FLT_OPERATION_REGISTRATION::new()
            .set_major_function(FLT_OPERATION_REGISTRATION::IRP_MJ_OPERATION_END),
    ]
};

const FILTER_REGISTRATION: FLT_REGISTRATION = FLT_REGISTRATION {
    Size: ::core::mem::size_of::<FLT_REGISTRATION>() as USHORT, /*sizeof*/
    Version: FLT_REGISTRATION_VERSION,
    Flags: 0,
    ContextRegistration: crate::mota::CONTEXT_REGISTRATION.as_ptr() as PVOID,
    OperationRegistration: CALLBACKS.as_ptr(),
    FilterUnloadCallback: RamonUnload,
    InstanceSetupCallback: RamonInstanceSetup,
    InstanceQueryTeardownCallback: RamonInstanceQueryTeardown,
    InstanceTeardownStartCallback: RamonInstanceTeardownStart,
    InstanceTeardownCompleteCallback: RamonInstanceTeardownComplete,
    GenerateFileNameCallback: null_mut(),
    NormalizeNameComponentCallback: null_mut(),
    NormalizeContextCleanupCallback: null_mut(),
    TransactionNotificationCallback: null_mut(),
    NormalizeNameComponentExCallback: null_mut(),
    SectionNotificationCallback: null_mut(),
};

extern "system" fn RamonUnload(flags: FLT_REGISTRATION_FLAGS) -> NTSTATUS {
    log::info!("ramon_unload");
    // A mandatory unload (forced/sc shutdown) proceeds even if this callback fails, so refusing is
    // only meaningful for a normal unload. For mandatory, attempt everything best-effort: an early
    // return would leave callbacks pointing into an image that is about to be freed.
    let mandatory = flags & FLTFL_FILTER_UNLOAD_MANDATORY != 0;
    unsafe {
        // unregister the WFP callout first: after this no classify can read the tree or enqueue
        let status = crate::net::stop();
        if !NT_SUCCESS!(status) {
            if !mandatory {
                // a callout/filter may still point into this image; let FltMgr keep it loaded
                log::error!("wfp teardown failed 0x{:08x}; refusing to unload", status);
                return status;
            }
            log::error!("wfp teardown failed 0x{:08x}; mandatory unload, continuing", status);
        }
        // removal waits for in-flight notify callbacks, so none can call send_message after this
        let status = crate::unregister_notify_callbacks();
        if !NT_SUCCESS!(status) {
            if !mandatory {
                log::error!("notify teardown failed 0x{:08x}; refusing to unload", status);
                return status;
            }
            log::error!("notify teardown failed 0x{:08x}; mandatory unload, continuing", status);
        }
        crate::send_message::stop_sender();
        // take under the lock, drop outside it (FltUnregisterFilter must not run at APC_LEVEL)
        let minifilter = S_MINIFILTER.lock().take();
        // FltUnregisterFilter has returned, so no section callback can run: free the remembered paths
        drop(minifilter);
        crate::section_sync::clear();
    }
    // unsafe {
    //     if !S_MINIFILTER.is_null() {
    //         (*S_MINIFILTER).deinit();
    //     }
    //
    //     let mem = S_MINIFILTER as PVOID;
    //     RtlZeroMemory(mem, size_of::<Minifilter>());
    //     ExFreePoolWithTag(mem, POOL_TAG);
    //
    //     S_MINIFILTER = null_mut();
    // }

    STATUS_SUCCESS
}

#[link_section = "PAGE"]
extern "system" fn RamonInstanceSetup(
    flt_objects: PFLT_RELATED_OBJECTS,
    _flags: FLT_INSTANCE_SETUP_FLAGS,
    volume_device_type: DEVICE_TYPE,
    _volume_filesystem_type: FLT_FILESYSTEM_TYPE,
) -> NTSTATUS {
    PAGED_CODE!();
    if flt_objects.is_null() {
        return STATUS_SUCCESS;
    }
    let device_type = volume_device_type as u32;
    // volume selection + per-instance state: refuse volumes that never carry agent content
    if !unsafe { crate::instance::attach(&*flt_objects, device_type) } {
        return crate::instance::DO_NOT_ATTACH;
    }
    INSTANCE_NUMBER.fetch_add(1, Ordering::Relaxed);
    log::info!("RamonInstanceSetup: attached device type 0x{:x}", device_type);
    STATUS_SUCCESS
}

#[link_section = "PAGE"]
extern "system" fn RamonInstanceQueryTeardown(
    _flt_objects: PFLT_RELATED_OBJECTS,
    _flags: FLT_INSTANCE_QUERY_TEARDOWN_FLAGS,
) -> NTSTATUS {
    log::info!("RamonInstanceQueryTeardown");

    PAGED_CODE!();

    //fileMon FltInstanceQueryTeardown

    log::info!("RamonInstanceQueryTeardown SUCCESS");
    STATUS_SUCCESS
}

#[link_section = "PAGE"]
extern "system" fn RamonInstanceTeardownStart(
    _flt_objects: PFLT_RELATED_OBJECTS,
    _flags: FLT_INSTANCE_TEARDOWN_FLAGS,
) -> NTSTATUS {
    log::info!(
        "RamonInstanceTeardownStart. Instance num: {}",
        INSTANCE_NUMBER.load(Ordering::Relaxed)
    );

    PAGED_CODE!();
    log::info!("RamonInstanceTeardownStart SUCCESS");
    STATUS_SUCCESS
}

#[link_section = "PAGE"]
extern "system" fn RamonInstanceTeardownComplete(
    flt_objects: PFLT_RELATED_OBJECTS,
    _flags: FLT_INSTANCE_TEARDOWN_FLAGS,
) -> NTSTATUS {
    PAGED_CODE!();
    if !flt_objects.is_null() {
        unsafe { crate::instance::detach(&*flt_objects) };
    }
    log::info!("RamonInstanceTeardownComplete");
    INSTANCE_NUMBER.fetch_sub(1, Ordering::Relaxed);
    STATUS_SUCCESS
}
