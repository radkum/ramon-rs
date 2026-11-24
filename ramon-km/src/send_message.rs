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
    locked::Locked,
    minifilter::{Minifilter, S_MINIFILTER},
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
// The thread swaps `queue` with its `batch` and sends the batch: neither ever grows.
const QUEUE_LEN: usize = 32768;
// queue full: callbacks wait for space, unless one event has been stuck longer than STALL (hung client)
const STALL: u64 = 1000 * 10_000;

struct Sender {
    queue: Vec<Vec<u8>>,
    spare: Vec<Vec<u8>>,
    wake: KEVENT,
    space: KEVENT,
    delivering_since: u64,
    stop: bool,
    dropped: u32,
    thread: HANDLE,
}

static G_SENDER: Locked<Sender> = Locked::new(Sender {
    queue: Vec::new(),
    spare: Vec::new(),
    // a zeroed KEVENT is valid only after KeInitializeEvent, which start_sender does before use
    wake: unsafe { mem::zeroed() },
    space: unsafe { mem::zeroed() },
    delivering_since: 0,
    stop: false,
    dropped: 0,
    thread: null_mut(),
});

/// The events live in the static for the driver's lifetime. The pointers are handed out so the
/// sender thread and `send_message` can wait on them without holding the mutex (a FAST_MUTEX must
/// not be held across `KeWaitForSingleObject`).
fn events() -> (*mut KEVENT, *mut KEVENT) {
    let sender = G_SENDER.lock();
    (&sender.wake as *const KEVENT as *mut KEVENT, &sender.space as *const KEVENT as *mut KEVENT)
}

pub(crate) unsafe fn start_sender() -> NTSTATUS {
    let mut sender = G_SENDER.lock();
    if sender.queue.try_reserve_exact(QUEUE_LEN).is_err()
        || sender.spare.try_reserve_exact(QUEUE_LEN).is_err()
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    KeInitializeEvent(&mut sender.wake, SynchronizationEvent, FALSE);
    KeInitializeEvent(&mut sender.space, NotificationEvent, FALSE);
    let mut oa: OBJECT_ATTRIBUTES = mem::zeroed();
    InitializeObjectAttributes(&mut oa, null_mut(), OBJ_KERNEL_HANDLE, null_mut(), null_mut());
    // the thread takes the same mutex, so it blocks until this guard is dropped
    PsCreateSystemThread(
        &mut sender.thread,
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
    let (wake, thread) = {
        let mut sender = G_SENDER.lock();
        sender.stop = true;
        (&mut sender.wake as *mut KEVENT, sender.thread)
    };
    if !thread.is_null() {
        KeSetEvent(wake, 0, FALSE);
        ZwWaitForSingleObject(thread, FALSE, null());
        ZwClose(thread);
        G_SENDER.lock().thread = null_mut();
    }
    let queue = {
        let mut sender = G_SENDER.lock();
        mem::take(&mut sender.queue)
    };
    drop(queue);
    drop(mem::take(&mut G_SENDER.lock().spare));
    let dropped = G_SENDER.lock().dropped;
    if dropped != 0 {
        log::warn!("events dropped (queue full or stopping): {}", dropped);
    }
}

pub(crate) fn send_message(event: Vec<u8>) {
    if event.is_empty() {
        return;
    }
    let mut event = event;
    let (wake, space) = events();
    loop {
        let mut pushed = false;
        {
            let mut sender = G_SENDER.lock();
            if sender.stop {
                sender.dropped += 1;
                return;
            }
            match sender.queue.push_within_capacity(event) {
                Ok(_) => {
                    // `Vec::new` does not allocate; keeping the value initialized lets the loop
                    // continue without a definite-initialization dance
                    event = Vec::new();
                    pushed = true;
                },
                Err(back) => event = back,
            }
            if !pushed {
                if sender.delivering_since != 0 && now() - sender.delivering_since > STALL {
                    sender.dropped += 1;
                    return;
                }
                unsafe { KeClearEvent(space) };
            }
        }
        unsafe { KeSetEvent(wake, 0, FALSE) };
        if pushed {
            return;
        }
        // short timeout: KeClearEvent above may race with the sender's KeSetEvent
        let timeout: i64 = -10 * 10_000;
        unsafe { KeWaitForSingleObject(space as PVOID, 0, 0, FALSE, &timeout) };
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
    let (wake, space) = events();
    let mut batch = {
        let mut sender = G_SENDER.lock();
        mem::take(&mut sender.spare)
    };
    loop {
        KeWaitForSingleObject(wake as PVOID, 0, 0, FALSE, null());
        loop {
            {
                let mut sender = G_SENDER.lock();
                if sender.stop {
                    return;
                }
                mem::swap(&mut sender.queue, &mut batch);
                if batch.is_empty() {
                    sender.delivering_since = 0;
                    break;
                }
                KeSetEvent(space, 0, FALSE);
            }
            for event in batch.drain(..) {
                {
                    let mut sender = G_SENDER.lock();
                    if sender.stop {
                        return;
                    }
                    sender.delivering_since = now();
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
    G_SENDER.lock().stop
}

/// Waits until the client takes the event; drops it only when no client is connected or on stop.
unsafe fn deliver(event: &[u8]) {
    // stop_sender runs before the minifilter is dropped, so the box outlives this call
    let ramon: *const Minifilter = {
        let minifilter = S_MINIFILTER.lock();
        minifilter.as_deref().map_or(null(), |ramon| ramon)
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
