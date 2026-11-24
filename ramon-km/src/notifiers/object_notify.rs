//! Process handle-open telemetry through `ObRegisterCallbacks` (pre-op, observation only: the
//! granted access is never stripped, which would require being registered as antimalware).
//!
//! IRQL: PASSIVE_LEVEL, once per handle open in the system, so the tag lookup runs first and an
//! untagged caller returns immediately.
use alloc::{string::String, vec::Vec};
use core::{mem, ptr::null_mut, slice};

use common::{
    event::{handle_open::HandleOpenEvent, Event},
    utils::try_extend,
};
use kernel_macros::HandleToU32;
use kernel_string::UNICODE_STRING;
use km_api_sys::ntddk::PsGetCurrentProcessId;
use winapi::{
    km::wdm::PEPROCESS,
    shared::ntdef::{HANDLE, NTSTATUS, PVOID},
};

use crate::{
    locked::Locked, notifiers::process_notify::session_tag_of, send_message::send_message,
    unicode_string,
};

// not declared in km-api-sys
extern "system" {
    static PsProcessType: PVOID;
    fn ObRegisterCallbacks(
        registration: *const ObCallbackRegistration,
        handle: *mut PVOID,
    ) -> NTSTATUS;
    fn ObUnRegisterCallbacks(handle: PVOID);
    fn PsGetProcessId(process: PEPROCESS) -> HANDLE;
    fn PsGetProcessCreateTimeQuadPart(process: PEPROCESS) -> i64;
    fn PsGetProcessImageFileName(process: PEPROCESS) -> *const u8;
}

const OB_OPERATION_HANDLE_CREATE: u32 = 1;
const OB_PREOP_SUCCESS: i32 = 0;
const OB_FLT_REGISTRATION_VERSION: u16 = 0x0100;
// Flags.KernelHandle: the open came from a driver, not from the current process
const OB_FLAG_KERNEL_HANDLE: u32 = 1;
// EPROCESS.ImageFileName is 15 bytes and not NUL-terminated when full
const IMAGE_FILE_NAME_LEN: usize = 15;
// only orders us against other object callbacks; the filter uses the same range as the minifilter
const OB_ALTITUDE: &str = "345102";

#[repr(C)]
struct ObPreOperationInformation {
    operation: u32,
    flags: u32,
    object: PVOID,
    object_type: PVOID,
    call_context: PVOID,
    // OB_PRE_OPERATION_PARAMETERS; for a create the first member is the requested access
    parameters: PVOID,
}

#[repr(C)]
struct ObOperationRegistration {
    // POBJECT_TYPE*, i.e. the import's value: a pointer to the POBJECT_TYPE cell
    object_type: PVOID,
    operations: u32,
    pre_operation: Option<extern "system" fn(PVOID, *const ObPreOperationInformation) -> i32>,
    post_operation: PVOID,
}

#[repr(C)]
struct ObCallbackRegistration {
    version: u16,
    operation_registration_count: u16,
    altitude: UNICODE_STRING,
    registration_context: PVOID,
    operation_registration: *const ObOperationRegistration,
}

// ObRegisterCallbacks keeps a pointer to the altitude buffer and the registration, so both live in
// kernel static memory. The callback never takes this lock.
struct Registration {
    operations: [ObOperationRegistration; 1],
    registration: ObCallbackRegistration,
    handle: PVOID,
}

static G_STATE: Locked<Registration> = Locked::new(Registration {
    operations: [unsafe { mem::zeroed() }],
    registration: unsafe { mem::zeroed() },
    handle: null_mut(),
});

pub(crate) unsafe fn start() -> NTSTATUS {
    G_STATE.init();
    let mut state = G_STATE.lock();
    state.operations[0].object_type = PsProcessType;
    state.operations[0].operations = OB_OPERATION_HANDLE_CREATE;
    state.operations[0].pre_operation = Some(OnProcessHandlePreOp);
    state.registration.version = OB_FLT_REGISTRATION_VERSION;
    state.registration.operation_registration_count = 1;
    state.registration.altitude = unicode_string(OB_ALTITUDE);
    state.registration.operation_registration = state.operations.as_ptr();
    ObRegisterCallbacks(&state.registration, &mut state.handle)
}

pub(crate) unsafe fn stop() {
    let mut state = G_STATE.lock();
    if !state.handle.is_null() {
        ObUnRegisterCallbacks(state.handle);
        state.handle = null_mut();
    }
}

/// Observes, never strips access: removing access rights needs an antimalware-protected driver.
extern "system" fn OnProcessHandlePreOp(
    _context: PVOID,
    info: *const ObPreOperationInformation,
) -> i32 {
    unsafe {
        let info = &*info;
        if info.operation != OB_OPERATION_HANDLE_CREATE
            || info.flags & OB_FLAG_KERNEL_HANDLE != 0
            || info.object.is_null()
            || info.parameters.is_null()
        {
            return OB_PREOP_SUCCESS;
        }
        // the machine opens process handles all the time: only a tagged caller is worth a line
        let caller = HandleToU32!(PsGetCurrentProcessId());
        let Some(session) = session_tag_of(caller) else {
            return OB_PREOP_SUCCESS;
        };
        let target = info.object as PEPROCESS;
        let event = HandleOpenEvent::new(
            caller,
            session,
            HandleToU32!(PsGetProcessId(target)),
            PsGetProcessCreateTimeQuadPart(target) as u64,
            *(info.parameters as *const u32),
            image_name(target),
        );
        send_message(event.serialize().unwrap_or_default());
    }
    OB_PREOP_SUCCESS
}

unsafe fn image_name(process: PEPROCESS) -> String {
    let name = PsGetProcessImageFileName(process);
    if name.is_null() {
        return String::new();
    }
    let bytes = slice::from_raw_parts(name, IMAGE_FILE_NAME_LEN);
    let len = bytes.iter().position(|b| *b == 0).unwrap_or(IMAGE_FILE_NAME_LEN);
    // the driver's alloc has no infallible push; image names are ASCII
    let mut buffer = Vec::new();
    if try_extend(&mut buffer, &bytes[..len]).is_err() {
        return String::new();
    }
    String::from_utf8(buffer).unwrap_or_default()
}
