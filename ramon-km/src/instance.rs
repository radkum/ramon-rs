//! Per-instance state and volume selection.
//!
//! One `FLT_INSTANCE_CONTEXT` is attached per volume FltMgr lets the filter attach to, holding the
//! volume's device type; it is freed in teardown. `RamonInstanceSetup` refuses volumes that never
//! carry agent content (network shares and CD-ROMs), so the filter does not attach to them. The
//! `Flt*InstanceContext` APIs are not in `km-api-sys`; they are declared here against the WDK ABI.
use core::{mem::size_of, ptr::null_mut};

use kernel_macros::NT_SUCCESS;
use km_api_sys::flt_kernel::{FLT_RELATED_OBJECTS, PFLT_FILTER, PFLT_INSTANCE};
use winapi::shared::ntdef::{NTSTATUS, PVOID};

use crate::mota::{context_entry, FltContextRegistration};

// FLT_CONTEXT_TYPE::FLT_INSTANCE_CONTEXT (fltKernel.h)
const FLT_INSTANCE_CONTEXT: u16 = 0x0002;
// FLT_SET_CONTEXT_OPERATION::FLT_SET_CONTEXT_KEEP_IF_EXISTS
const FLT_SET_CONTEXT_KEEP_IF_EXISTS: i32 = 1;
// STATUS_FLT_DO_NOT_ATTACH (ntstatus.h): the instance-setup callback refuses a volume
pub(crate) const DO_NOT_ATTACH: NTSTATUS = 0xC01C_000Fu32 as i32;
// FILE_DEVICE_* (wdm.h)
const FILE_DEVICE_CD_ROM_FILE_SYSTEM: u32 = 0x0000_0003;
const FILE_DEVICE_NETWORK_FILE_SYSTEM: u32 = 0x0000_0014;

extern "system" {
    fn FltAllocateContext(
        filter: PFLT_FILTER,
        context_type: u16,
        context_size: usize,
        pool_type: u32,
        returned_context: *mut PVOID,
    ) -> NTSTATUS;
    fn FltSetInstanceContext(
        instance: PFLT_INSTANCE,
        operation: i32,
        new_context: PVOID,
        old_context: *mut PVOID,
    ) -> NTSTATUS;
    fn FltDeleteInstanceContext(instance: PFLT_INSTANCE, old_context: *mut PVOID) -> NTSTATUS;
    fn FltReleaseContext(context: PVOID);
}

/// Per-instance state: the volume's device type (a small copyable value, no cleanup needed).
#[repr(C)]
pub(crate) struct InstanceContext {
    device_type: u32,
}

pub(crate) const INSTANCE_CONTEXT_ENTRY: FltContextRegistration = context_entry(
    FLT_INSTANCE_CONTEXT,
    null_mut(),
    size_of::<InstanceContext>(),
    u32::from_ne_bytes(*b"ramI"),
);

/// Volume selection + per-instance state: returns false when the volume must not be attached to.
pub(crate) unsafe fn attach(flt_objects: &FLT_RELATED_OBJECTS, device_type: u32) -> bool {
    if device_type == FILE_DEVICE_NETWORK_FILE_SYSTEM
        || device_type == FILE_DEVICE_CD_ROM_FILE_SYSTEM
    {
        log::info!("instance: skipping device type 0x{:x}", device_type);
        return false;
    }
    let mut context: PVOID = null_mut();
    let status = FltAllocateContext(
        flt_objects.Filter,
        FLT_INSTANCE_CONTEXT,
        size_of::<InstanceContext>(),
        0, // NonPagedPool
        &mut context,
    );
    if !NT_SUCCESS!(status) || context.is_null() {
        return true; // still attach; the context is best-effort
    }
    core::ptr::write(context as *mut InstanceContext, InstanceContext { device_type });
    let mut old: PVOID = null_mut();
    FltSetInstanceContext(flt_objects.Instance, FLT_SET_CONTEXT_KEEP_IF_EXISTS, context, &mut old);
    FltReleaseContext(context);
    if !old.is_null() {
        FltReleaseContext(old);
    }
    true
}

/// Frees the per-instance context, logging the volume device type it carried.
pub(crate) unsafe fn detach(flt_objects: &FLT_RELATED_OBJECTS) {
    let mut old: PVOID = null_mut();
    FltDeleteInstanceContext(flt_objects.Instance, &mut old);
    if !old.is_null() {
        let device_type = (*(old as *const InstanceContext)).device_type;
        log::info!("instance: detaching device type 0x{:x}", device_type);
        FltReleaseContext(old);
    }
}
