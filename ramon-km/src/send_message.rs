//! Event queue between the notify callbacks and user mode.
//!
//! Callbacks only enqueue; a dedicated system thread sends with `FltSendMessage`, so a slow or
//! stuck client never runs inside a callback. `send_message` may be called from the callbacks
//! below (IRQL <= APC_LEVEL): the queue is protected by a FAST_MUTEX and the wait for space uses
//! a kernel event, never a spin. When no client drains the queue for `STALL`, events are dropped
//! and counted instead of blocking the system forever.
use alloc::vec::Vec;
use core::{
    mem,
    ptr::{null, null_mut},
};

use kernel_fast_mutex::auto_lock::AutoLock;
use kernel_macros::NT_SUCCESS;
use km_api_sys::{
    flt_kernel::{FltSendMessage, CONST_PVOID},
    wmd::{KeInitializeEvent, ZwClose, LARGE_INTEGER, PLARGE_INTEGER},
};
use winapi::{
    km::wdm::{NotificationEvent, SynchronizationEvent, KEVENT, PKEVENT},
    shared::{
        ntdef::{
            InitializeObjectAttributes, BOOLEAN, FALSE, HANDLE, NTSTATUS, OBJECT_ATTRIBUTES,
            OBJ_KERNEL_HANDLE, PVOID,
        },
        ntstatus::{STATUS_INSUFFICIENT_RESOURCES, STATUS_SUCCESS, STATUS_TIMEOUT},
    },
};

use crate::{
    minifilter::{Minifilter, S_MINIFILTER},
    G_MUTEX,
};

// not declared in km-api-sys
extern "system" {
    fn PsCreateSystemThread(
        thread: *mut HANDLE,
        access: u32,
        attributes: *mut OBJECT_ATTRIBUTES,
        process: HANDLE,
        client_id: PVOID,
        start: extern "system" fn(PVOID),
        context: PVOID,
    ) -> NTSTATUS;
    fn PsTerminateSystemThread(status: NTSTATUS) -> NTSTATUS;
    fn KeSetEvent(event: PKEVENT, increment: i32, wait: BOOLEAN) -> i32;
    fn KeWaitForSingleObject(
        object: PVOID,
        reason: u32,
        mode: i8,
        alertable: BOOLEAN,
        timeout: *const i64,
    ) -> NTSTATUS;
    fn ZwWaitForSingleObject(handle: HANDLE, alertable: BOOLEAN, timeout: *const i64) -> NTSTATUS;
    fn KeClearEvent(event: PKEVENT);
    fn KeQueryInterruptTimePrecise(qpc: *mut u64) -> u64;
    fn PsGetCurrentThread() -> PVOID;
    fn KeSetPriorityThread(thread: PVOID, priority: i32) -> i32;
}
const SYNCHRONIZE: u32 = 0x0010_0000;
const LOW_REALTIME_PRIORITY: i32 = 16;

// callbacks only queue events; one thread sends them, so a slow client never blocks the system.
// The thread swaps G_QUEUE with G_SPARE and sends the batch: neither ever grows.
const QUEUE_LEN: usize = 32768;
static mut G_QUEUE: Vec<Vec<u8>> = Vec::new();
static mut G_SPARE: Vec<Vec<u8>> = Vec::new();
static mut G_WAKE: KEVENT = unsafe { mem::zeroed() };
// queue full: callbacks wait for space, unless one event has been stuck longer than STALL (hung client)
static mut G_SPACE: KEVENT = unsafe { mem::zeroed() };
static mut G_DELIVERING_SINCE: u64 = 0;
const STALL: u64 = 1000 * 10_000;
static mut G_STOP: bool = false;
static mut G_DROPPED: u32 = 0;
static mut G_THREAD: HANDLE = null_mut();

pub(crate) unsafe fn start_sender() -> NTSTATUS {
    if G_QUEUE.try_reserve_exact(QUEUE_LEN).is_err()
        || G_SPARE.try_reserve_exact(QUEUE_LEN).is_err()
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    KeInitializeEvent(&mut G_WAKE, SynchronizationEvent, FALSE);
    KeInitializeEvent(&mut G_SPACE, NotificationEvent, FALSE);
    let mut oa: OBJECT_ATTRIBUTES = mem::zeroed();
    InitializeObjectAttributes(&mut oa, null_mut(), OBJ_KERNEL_HANDLE, null_mut(), null_mut());
    PsCreateSystemThread(
        &mut G_THREAD,
        SYNCHRONIZE,
        &mut oa,
        null_mut(),
        null_mut(),
        sender_thread,
        null_mut(),
    )
}

/// Call after the notify callbacks are removed and before the minifilter is dropped.
pub(crate) unsafe fn stop_sender() {
    {
        let _locker = AutoLock::new(&mut G_MUTEX);
        G_STOP = true;
    }
    if !G_THREAD.is_null() {
        KeSetEvent(&mut G_WAKE, 0, FALSE);
        ZwWaitForSingleObject(G_THREAD, FALSE, null());
        ZwClose(G_THREAD);
        G_THREAD = null_mut();
    }
    let queue = {
        let _locker = AutoLock::new(&mut G_MUTEX);
        mem::take(&mut G_QUEUE)
    };
    drop(queue);
    drop(mem::take(&mut G_SPARE));
    if G_DROPPED != 0 {
        log::warn!("events dropped (queue full or stopping): {}", G_DROPPED);
    }
}

pub(crate) fn send_message(event: Vec<u8>) {
    if event.is_empty() {
        return;
    }
    let mut event = event;
    unsafe {
        loop {
            {
                let _locker = AutoLock::new(&mut G_MUTEX);
                if G_STOP {
                    G_DROPPED += 1;
                    return;
                }
                match G_QUEUE.push_within_capacity(event) {
                    Ok(_) => break,
                    Err(back) => event = back,
                }
                if G_DELIVERING_SINCE != 0 && now() - G_DELIVERING_SINCE > STALL {
                    G_DROPPED += 1;
                    return;
                }
                KeClearEvent(&mut G_SPACE);
            }
            KeSetEvent(&mut G_WAKE, 0, FALSE);
            // short timeout: KeClearEvent above may race with the sender's KeSetEvent
            let timeout: i64 = -10 * 10_000;
            KeWaitForSingleObject(&mut G_SPACE as *mut KEVENT as PVOID, 0, 0, FALSE, &timeout);
        }
        KeSetEvent(&mut G_WAKE, 0, FALSE);
    }
}

extern "system" fn sender_thread(_context: PVOID) {
    unsafe {
        run();
        PsTerminateSystemThread(STATUS_SUCCESS);
    }
}

// separate from sender_thread: PsTerminateSystemThread does not return, so the batch is dropped here
unsafe fn run() {
    // at normal priority a burst of new processes starves the sender for seconds
    KeSetPriorityThread(PsGetCurrentThread(), LOW_REALTIME_PRIORITY);
    let mut batch = mem::take(&mut G_SPARE);
    loop {
        KeWaitForSingleObject(&mut G_WAKE as *mut KEVENT as PVOID, 0, 0, FALSE, null());
        loop {
            {
                let _locker = AutoLock::new(&mut G_MUTEX);
                if G_STOP {
                    return;
                }
                mem::swap(&mut G_QUEUE, &mut batch);
                if batch.is_empty() {
                    G_DELIVERING_SINCE = 0;
                    break;
                }
            }
            KeSetEvent(&mut G_SPACE, 0, FALSE);
            for event in batch.drain(..) {
                {
                    let _locker = AutoLock::new(&mut G_MUTEX);
                    if G_STOP {
                        return;
                    }
                    G_DELIVERING_SINCE = now();
                }
                deliver(&event);
            }
        }
    }
}

fn now() -> u64 {
    unsafe { KeQueryInterruptTimePrecise(&mut 0) }
}

unsafe fn is_stopping() -> bool {
    let _locker = AutoLock::new(&mut G_MUTEX);
    G_STOP
}

/// Waits until the client takes the event; drops it only when no client is connected or on stop.
unsafe fn deliver(event: &[u8]) {
    // stop_sender runs before the minifilter is dropped, so the box outlives this call
    let ramon: *const Minifilter = {
        let _locker = AutoLock::new(&mut G_MUTEX);
        S_MINIFILTER.as_deref().map_or(null(), |ramon| ramon)
    };
    let Some(ramon) = ramon.as_ref() else {
        return;
    };
    while ramon.is_comm_active() {
        // negative = relative, in 100ns units: wake up every 100ms to check for stop
        let mut timeout = LARGE_INTEGER::new_from_i64(-100 * 10_000);
        let s = FltSendMessage(
            ramon.filter_handle,
            &ramon.client_port,
            event.as_ptr() as CONST_PVOID,
            event.len() as u32,
            null_mut(),
            null_mut(),
            &mut timeout as PLARGE_INTEGER as PVOID,
        );
        if s != STATUS_TIMEOUT || is_stopping() {
            if !NT_SUCCESS!(s) {
                log::warn!("FltSendMessage failed, event dropped. Status: 0x{:08x}", s);
            }
            return;
        }
    }
}
