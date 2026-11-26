//! RAMON - an example Windows minifilter in Rust (no_std, cdylib).
//!
//! `DriverEntry` runs at PASSIVE_LEVEL and registers the notify callbacks, the communication
//! port and the sender thread. Everything that reaches user mode goes through
//! `send_message::send_message`, which is safe to call from any callback.
#![no_std]
#![feature(allocator_api)]
#![feature(vec_push_within_capacity)]
#![allow(non_snake_case)]
// the driver keeps its state in Locked/SpinLocked; do not let a new `static mut` slip in
#![deny(static_mut_refs)]

mod cleaner;

mod guardrail;
mod ioctl_code;
mod irp;
mod libm_shim;
mod locked;
mod logger;
mod minifilter;
mod mirage;
mod mota;
mod net;
mod notifiers;
mod np_alloc;
mod section_sync;
mod send_message;
mod spinlock;

use notifiers::{
    clear_tree, init_tree, start_object_notify, stop_object_notify, OnImageLoadNotify,
    OnProcessNotify, OnRegistryNotify,
};

extern crate alloc;

use core::ptr::null_mut;

/// kernel-init deliver a few elements (eg. panic implementation) necessary to run code in kernel
#[allow(unused_imports)]
use kernel_init;
use kernel_macros::NT_SUCCESS;
use kernel_string::UNICODE_STRING;
use km_api_sys::{
    ntddk::{
        PsRemoveLoadImageNotifyRoutine, PsSetCreateProcessNotifyRoutineEx,
        PsSetLoadImageNotifyRoutine,
    },
    wmd::{CmUnRegisterCallback, LARGE_INTEGER},
};
use log::LevelFilter;
use winapi::{
    km::wdm::{DEVICE_OBJECT, DRIVER_OBJECT, IRP, IRP_MJ},
    shared::{
        ntdef::{FALSE, NTSTATUS, PVOID, TRUE},
        ntstatus::STATUS_SUCCESS,
    },
};

use crate::{
    cleaner::Cleaner, irp::complete_irp_success, locked::Locked, logger::KernelLogger,
    minifilter::Minifilter,
};

#[allow(dead_code)]
pub(crate) const POOL_TAG: u32 = u32::from_ne_bytes(*b"RDER");

// km-api-sys declares the cookie as `&LARGE_INTEGER`. That is an out-parameter, and a shared
// reference lets the optimizer assume the callee does not write to it: the cookie was stored as
// zero and CmUnRegisterCallback(0) silently failed, leaving the registry callback registered after
// the driver image unloaded (bugcheck 0xCE). Declare the real ABI here so the write is visible.
extern "system" {
    fn CmRegisterCallbackEx(
        Function: PVOID,
        Altitude: &UNICODE_STRING,
        Driver: &DRIVER_OBJECT,
        Context: PVOID,
        Cookie: *mut LARGE_INTEGER,
        Reserved: PVOID,
    ) -> NTSTATUS;
}

// the registry callback cookie: written at load, read by the registry callback and on unload
pub(crate) static G_COOKIE: Locked<LARGE_INTEGER> = Locked::new(LARGE_INTEGER::new());

// Unregistering is not idempotent: a retried unload must resume after the last callback that was
// actually removed, not fail on the already-removed one.
struct NotifyState {
    process_removed: bool,
    image_removed: bool,
    registry_removed: bool,
    object_removed: bool,
}

static G_NOTIFY: Locked<NotifyState> = Locked::new(NotifyState {
    process_removed: false,
    image_removed: false,
    registry_removed: false,
    object_removed: false,
});

#[link_section = "INIT"]
#[no_mangle]
pub unsafe extern "system" fn DriverEntry(
    driver: &mut DRIVER_OBJECT,
    _path: *const UNICODE_STRING,
) -> NTSTATUS {
    KernelLogger::init(LevelFilter::Warn).expect("Failed to initialize logger");

    log::info!("START Ramon");
    G_COOKIE.init();
    G_NOTIFY.init();
    // before start_sender: the sender's deliver() locks the minifilter slot
    minifilter::init();

    let hello_world = unicode_string("Hello World!");
    log::info!("{}", hello_world);

    init_tree();
    guardrail::init();
    mirage::init();
    mota::init();
    section_sync::init();

    //--------------------DISPATCH_ROUTINES-----------------------
    driver.MajorFunction[IRP_MJ::CREATE as usize] = Some(DispatchCreateClose);
    driver.MajorFunction[IRP_MJ::CLOSE as usize] = Some(DispatchCreateClose);
    // no DriverUnload: FltRegisterFilter replaces it, unload goes through FilterUnloadCallback (RamonUnload)

    //--------------------INIT MINIFILTER-----------------------
    #[allow(unused_assignments)]
    let mut status = STATUS_SUCCESS;

    let mut cleaner = Cleaner::new();
    loop {
        status = send_message::start_sender();
        if !NT_SUCCESS!(status) {
            log::info!("failed to start sender thread 0x{:08x}", status);
            break;
        }

        //--------------------PROCESS NOTIFY-----------------------
        status = PsSetCreateProcessNotifyRoutineEx(OnProcessNotify, FALSE);

        if NT_SUCCESS!(status) {
            cleaner.init_process_create_callback(OnProcessNotify);
        } else {
            log::info!("failed to create process nofity rountine 0x{:08x}", status);
            break;
        }

        //--------------------IMAGE NOTIFY-----------------------
        status = PsSetLoadImageNotifyRoutine(OnImageLoadNotify);

        if NT_SUCCESS!(status) {
            cleaner.init_image_load_callback(OnImageLoadNotify);
        } else {
            log::info!("failed to create image load routine 0x{:08x}", status);
            break;
        }

        //--------------------REGISTRY NOTIFY-----------------------
        let altitude = unicode_string("7657.124");
        let mut cookie = LARGE_INTEGER::new();
        status = CmRegisterCallbackEx(
            OnRegistryNotify as PVOID,
            &altitude,
            driver,
            null_mut(),
            &mut cookie,
            null_mut(),
        );

        if NT_SUCCESS!(status) {
            // tiny window: a registry callback on another CPU can fire before this assignment and
            // see cookie = 0, in which case it skips the event (CmCallbackGetKeyObjectIDEx fails).
            // Benign - no crash, at most one missed registry event in the load window.
            *G_COOKIE.lock() = cookie;
            cleaner.init_registry_callback(cookie);
        } else {
            log::info!("failed to create registry routine 0x{:08x}", status);
            break;
        }

        //--------------------OBJECT NOTIFY (process handle opens)-----------------------
        status = start_object_notify();

        if NT_SUCCESS!(status) {
            cleaner.init_object_callback();
        } else {
            log::info!("failed to register object callbacks 0x{:08x}", status);
            break;
        }

        //#[allow(unused_assignments)]
        status = Minifilter::create(driver);
        break;
    }

    //clean if initialization failed
    if NT_SUCCESS!(status) {
        // WFP is telemetry: a registration failure leaves the rest of the sensor working
        let wfp = net::start(driver as *mut DRIVER_OBJECT);
        if !NT_SUCCESS!(wfp) {
            log::warn!("wfp callout not registered. Status: 0x{:08x}", wfp);
        }
        log::info!("SUCCESS");
    } else {
        cleaner.clean();
        clear_tree();
        send_message::stop_sender();
    }

    status
}

// UNICODE_STRING::create leaks its ANSI copy (kernel-string); the UTF-16 path frees its copy
pub(crate) fn unicode_string(s: &str) -> UNICODE_STRING {
    let mut buf = [0u16; 64];
    let mut len = 0;
    for (dst, c) in buf.iter_mut().zip(s.encode_utf16()) {
        *dst = c;
        len += 1;
    }
    UNICODE_STRING::from(&buf[..len])
}

/*************************************************************************
                    Dispatch  routines.
*************************************************************************/
/// Returns the first failure: a callback that could not be removed would outlive the image, so the
/// caller must keep the driver loaded instead of letting FltMgr detach it. Each successful removal
/// is remembered, so a retry resumes instead of failing on an already-removed routine.
pub(crate) unsafe fn unregister_notify_callbacks() -> NTSTATUS {
    log::info!("rust_unload");

    let (process_removed, image_removed, registry_removed, object_removed) = {
        let state = G_NOTIFY.lock();
        (state.process_removed, state.image_removed, state.registry_removed, state.object_removed)
    };

    if !process_removed {
        let status = PsSetCreateProcessNotifyRoutineEx(OnProcessNotify, TRUE);
        if !NT_SUCCESS!(status) {
            log::warn!(
                "PsSetCreateProcessNotifyRoutineEx(remove) failed. Status: 0x{:08x}",
                status
            );
            return status;
        }
        G_NOTIFY.lock().process_removed = true;
        clear_tree();
    }

    //PsRemoveCreateThreadNotifyRoutine(OnThreadNotify);

    if !image_removed {
        let status = PsRemoveLoadImageNotifyRoutine(OnImageLoadNotify);
        if !NT_SUCCESS!(status) {
            log::warn!("PsRemoveLoadImageNotifyRoutine failed. Status: 0x{:08x}", status);
            return status;
        }
        G_NOTIFY.lock().image_removed = true;
    }

    if !registry_removed {
        // copy the cookie and release the lock first: CmUnRegisterCallback waits for in-flight
        // registry callbacks, and one of them may be waiting for this lock
        let cookie = *G_COOKIE.lock();
        let status = CmUnRegisterCallback(cookie);
        if !NT_SUCCESS!(status) {
            log::warn!("CmUnRegisterCallback failed. Status: 0x{:08x}", status);
            return status;
        }
        G_NOTIFY.lock().registry_removed = true;
    }

    if !object_removed {
        stop_object_notify();
        G_NOTIFY.lock().object_removed = true;
    }
    STATUS_SUCCESS
}

extern "system" fn DispatchCreateClose(_driver: &mut DEVICE_OBJECT, irp: &mut IRP) -> NTSTATUS {
    complete_irp_success(irp)
}
