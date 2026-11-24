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
};
use file_monitor::FileMonitor;
use kernel_macros::{HandleToU32, NT_SUCCESS, PAGED_CODE};
use km_api_sys::{flt_kernel::*, ntddk::PsGetCurrentProcessId};
use winapi::{
    km::wdm::{DEVICE_TYPE, PDRIVER_OBJECT},
    shared::{
        ntdef::{
            InitializeObjectAttributes, NTSTATUS, OBJECT_ATTRIBUTES, OBJ_CASE_INSENSITIVE,
            OBJ_KERNEL_HANDLE, POBJECT_ATTRIBUTES, PUCHAR, PULONG, PVOID, ULONG, USHORT,
        },
        ntstatus::{
            STATUS_INSUFFICIENT_RESOURCES, STATUS_INVALID_PARAMETER, STATUS_NOT_FOUND,
            STATUS_SUCCESS,
        },
    },
    um::winnt::PSECURITY_DESCRIPTOR,
};

use crate::{
    locked::Locked,
    notifiers::{adopt, adopt_tag, MmCopyMemory, MM_COPY_MEMORY_VIRTUAL},
    unicode_string,
};

pub(crate) type PMINIFILTER = *mut Minifilter;
pub(crate) static S_MINIFILTER: Locked<Option<Box<Minifilter>>> = Locked::new(None);
static INSTANCE_NUMBER: AtomicUsize = AtomicUsize::new(0);

pub(crate) struct Minifilter {
    pub filter_handle: PFLT_FILTER,
    server_port: PFLT_PORT,
    pub client_port: PFLT_PORT,
    //on_command: FN,
    //context: PVOID
}

impl Minifilter {
    fn new_empty() -> Minifilter {
        Self { filter_handle: null_mut(), server_port: null_mut(), client_port: null_mut() }
    }

    pub(crate) fn create(driver: PDRIVER_OBJECT) -> NTSTATUS {
        unsafe {
            log::info!("Minifilter::factory");
            S_MINIFILTER.init();
            let minifilter = match Box::try_new(Minifilter::new_empty()) {
                Ok(minifilter) => minifilter,
                Err(_) => return STATUS_INSUFFICIENT_RESOURCES,
            };
            // do not hold the lock across init: registering the filter can run instance setup,
            // which must not re-enter the same FAST_MUTEX
            let minifilter = {
                let mut slot = S_MINIFILTER.lock();
                *slot = Some(minifilter);
                slot.as_mut().map_or(null_mut(), |minifilter| &mut **minifilter as *mut Minifilter)
            };
            let status = (*minifilter).init(driver);

            if !NT_SUCCESS!(status) {
                log::info!("failed to init minifilter. Status: 0x{:08x}", status);
                // take under the lock, drop outside it: Minifilter::drop calls FltUnregisterFilter
                let failed = S_MINIFILTER.lock().take();
                drop(failed);
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
    pub(crate) fn is_comm_active(&self) -> bool {
        !self.server_port.is_null() && !self.client_port.is_null()
    }

    //comm callbacks
    pub(crate) unsafe extern "system" fn on_connect(
        client_port: PFLT_PORT,
        server_port_cookie: PVOID,
        _connection_context: PVOID,
        _size_of_context: ULONG,
        connection_port_cookie: PPVOID,
    ) -> NTSTATUS {
        log::info!("Client Port connected");
        if server_port_cookie.is_null() {
            log::warn!("server_port_cookie is null");
            return STATUS_INVALID_PARAMETER;
        }

        let minifilter = server_port_cookie as PMINIFILTER;
        (*minifilter).client_port = client_port;

        // on_connect runs in the connecting client's context: remember its pid so MOTA ignores it
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

        FltCloseClientPort((*l_this).filter_handle, &mut (*l_this).client_port);
        (*l_this).client_port = null_mut();
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
        loop {
            status = FltBuildDefaultSecurityDescriptor(&mut port_security, FLT_PORT_ALL_ACCESS);
            if !NT_SUCCESS!(status) {
                log::warn!("failed to build security descriptor. Status: {}", status);
                break;
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
                break;
            }

            log::info!("SUCCESS to create comm port. Port name: {}", port_name);
            log::info!("SUCCESS to create comm port. Port name (degug): {:?}", port_name);
            break;
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

const CALLBACKS: &'static [FLT_OPERATION_REGISTRATION] = {
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

extern "system" fn RamonUnload(_flags: FLT_REGISTRATION_FLAGS) -> NTSTATUS {
    log::info!("ramon_unload");
    unsafe {
        // unregister the WFP callout first: after this no classify can read the tree or enqueue
        crate::net::stop();
        // removal waits for in-flight notify callbacks, so none can call send_message after this
        crate::unregister_notify_callbacks();
        crate::send_message::stop_sender();
        // take under the lock send_message holds; drop outside it (FltUnregisterFilter must not run at APC_LEVEL)
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
    _flt_objects: PFLT_RELATED_OBJECTS,
    _flags: FLT_INSTANCE_SETUP_FLAGS,
    _volume_device_type: DEVICE_TYPE,
    _volume_filesystem_type: FLT_FILESYSTEM_TYPE,
) -> NTSTATUS {
    log::info!("RamonInstanceSetup");
    INSTANCE_NUMBER.fetch_add(1, Ordering::Relaxed);
    PAGED_CODE!();
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
    _flt_objects: PFLT_RELATED_OBJECTS,
    _flags: FLT_INSTANCE_TEARDOWN_FLAGS,
) -> NTSTATUS {
    log::info!("RamonInstanceTeardownComplete");

    PAGED_CODE!();
    log::info!("RamonInstanceTeardownComplete SUCCESS");
    INSTANCE_NUMBER.fetch_sub(1, Ordering::Relaxed);
    STATUS_SUCCESS
}
