//! RAMON - an example Windows minifilter in Rust (no_std, cdylib).
//!
//! `DriverEntry` runs at PASSIVE_LEVEL and registers the notify callbacks, the communication
//! port and the sender thread. Everything that reaches user mode goes through
//! `send_message::send_message`, which is safe to call from any callback.
#![no_std]
#![feature(allocator_api)]
#![feature(vec_push_within_capacity)]
#![allow(non_snake_case)]
#![allow(static_mut_refs)]

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

use kernel_fast_mutex::{fast_mutex::FastMutex, locker::Locker};
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
    wmd::{CmRegisterCallbackEx, CmUnRegisterCallback, LARGE_INTEGER},
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
    cleaner::Cleaner, irp::complete_irp_success, logger::KernelLogger, minifilter::Minifilter,
};

#[allow(dead_code)]
pub(crate) const POOL_TAG: u32 = u32::from_ne_bytes(*b"RDER");

static mut G_MUTEX: FastMutex = FastMutex::new();
//static mut G_PROCESS_NAMES: Option<BTreeSet<ULONG>> = None;
static mut G_COOKIE: LARGE_INTEGER = LARGE_INTEGER::new();

#[link_section = "INIT"]
#[no_mangle]
pub unsafe extern "system" fn DriverEntry(
    driver: &mut DRIVER_OBJECT,
    _path: *const UNICODE_STRING,
) -> NTSTATUS {
    KernelLogger::init(LevelFilter::Warn).expect("Failed to initialize logger");

    log::info!("START Ramon");

    let hello_world = unicode_string("Hello World!");
    log::info!("{}", hello_world);

    //--------------------GLOBALS--------------------------------
    G_MUTEX.Init();
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
        status = CmRegisterCallbackEx(
            OnRegistryNotify as PVOID,
            &altitude,
            driver,
            null_mut(),
            &G_COOKIE,
            null_mut(),
        );

        if NT_SUCCESS!(status) {
            cleaner.init_registry_callback(G_COOKIE);
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
pub(crate) unsafe fn unregister_notify_callbacks() {
    log::info!("rust_unload");

    PsSetCreateProcessNotifyRoutineEx(OnProcessNotify, TRUE);
    clear_tree();

    //PsRemoveCreateThreadNotifyRoutine(OnThreadNotify);

    PsRemoveLoadImageNotifyRoutine(OnImageLoadNotify);

    CmUnRegisterCallback(G_COOKIE);

    stop_object_notify();
}

extern "system" fn DispatchCreateClose(_driver: &mut DEVICE_OBJECT, irp: &mut IRP) -> NTSTATUS {
    complete_irp_success(irp)
}
