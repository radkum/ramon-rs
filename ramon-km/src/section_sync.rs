//! Writable memory-mapped files bypass the write path: the flush is paging I/O in a system thread, with
//! no agent tag, at DISPATCH_LEVEL, so `IRP_MJ_WRITE` cannot attribute it (and could not allocate the
//! event there). Watch the section lifecycle instead: a tagged process creating a writable section over
//! a telemetry file is remembered; when a paging write to it completes, its slot is marked with an
//! atomic bit (safe at DISPATCH) and reported from the next PASSIVE callback. A final report is emitted
//! when the section is released, so a mapping that never sees a PASSIVE drain is still covered.
#![allow(static_mut_refs)]

use alloc::{string::String, vec::Vec};
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use ariadne::SessionTag;
use common::utils::try_to_string;

use crate::locked::Locked;

// writable sections are rare and short-lived, so a small ring is enough; it holds a path per entry.
// The pending bitset is one u64, so the capacity must not exceed 64.
const CAPACITY: usize = 64;
const _: () = assert!(CAPACITY <= 64);

struct Entry {
    file_object: usize,
    session: SessionTag,
    pid: u32,
    path: String,
}

const EMPTY: Option<Entry> = None;
struct Ring {
    entries: [Option<Entry>; CAPACITY],
    next: usize,
}

static G_RING: Locked<Ring> = Locked::new(Ring { entries: [EMPTY; CAPACITY], next: 0 });
// the FILE_OBJECT of each slot, readable without the lock so a DISPATCH write can find its slot
static G_OBJECTS: [AtomicUsize; CAPACITY] = [const { AtomicUsize::new(0) }; CAPACITY];
// bit `i` set: a paging write to slot `i` is pending a PASSIVE report
static G_PENDING: AtomicU64 = AtomicU64::new(0);

fn slot(index: usize) -> &'static AtomicUsize {
    // G_OBJECTS lives for the whole driver; a shared atomic reference is sound across threads
    &G_OBJECTS[index]
}

fn clear_pending(index: usize) {
    G_PENDING.fetch_and(!(1u64 << index), Ordering::AcqRel);
}

pub(crate) unsafe fn init() {
    G_RING.init();
    {
        let mut ring = G_RING.lock();
        ring.entries = [EMPTY; CAPACITY];
        ring.next = 0;
    }
    for index in 0..CAPACITY {
        slot(index).store(0, Ordering::Release);
    }
    G_PENDING.store(0, Ordering::Release);
}

/// A tagged process created a writable section over `path`: remember it until the section is released.
pub(crate) fn remember(file_object: usize, session: SessionTag, pid: u32, path: String) {
    let mut ring = G_RING.lock();
    for index in 0..CAPACITY {
        if ring.entries[index].as_ref().is_some_and(|e| e.file_object == file_object) {
            ring.entries[index] = Some(Entry { file_object, session, pid, path });
            slot(index).store(file_object, Ordering::Release);
            return;
        }
    }
    let index = ring.next;
    ring.entries[index] = Some(Entry { file_object, session, pid, path });
    slot(index).store(file_object, Ordering::Release);
    // a reused slot carries no pending write from its previous occupant
    clear_pending(index);
    ring.next = (index + 1) % CAPACITY;
}

/// Drops every remembered section; called on unload, after the filter stops receiving callbacks, so the
/// paths (heap) are freed before the driver image goes away.
pub(crate) unsafe fn clear() {
    {
        let mut ring = G_RING.lock();
        ring.entries = [EMPTY; CAPACITY];
        ring.next = 0;
    }
    for index in 0..CAPACITY {
        slot(index).store(0, Ordering::Release);
    }
    G_PENDING.store(0, Ordering::Release);
}

/// The section was released: hand back its entry so the caller can report the write. Runs at
/// PASSIVE_LEVEL (the release callback), so moving the path out and dropping it is safe.
pub(crate) fn take(file_object: usize) -> Option<(SessionTag, u32, String)> {
    let mut ring = G_RING.lock();
    for index in 0..CAPACITY {
        if ring.entries[index].as_ref().is_some_and(|e| e.file_object == file_object) {
            let entry = ring.entries[index].take()?;
            slot(index).store(0, Ordering::Release);
            return Some((entry.session, entry.pid, entry.path));
        }
    }
    None
}

/// A paging write to `file_object` completed. Called from the write post-op, possibly at DISPATCH_LEVEL,
/// so it only touches atomics: no lock, no allocation. The write is reported by the next `drain_written`.
pub(crate) fn mark_written(file_object: usize) {
    if file_object == 0 {
        return;
    }
    for index in 0..CAPACITY {
        if slot(index).load(Ordering::Acquire) == file_object {
            G_PENDING.fetch_or(1u64 << index, Ordering::Release);
            return;
        }
    }
}

/// Reports every write remembered by `mark_written` and clears the pending bits. PASSIVE_LEVEL only
/// (copies each path). A section released before the drain is skipped: its release already reports it.
/// The collected paths go on the heap: this runs on a write-completion stack that is already deep, and
/// a large stack frame here overflows the kernel stack (bugcheck 0x50, seen in the lab).
pub(crate) fn drain_written(mut emit: impl FnMut(SessionTag, u32, String)) {
    let pending = G_PENDING.swap(0, Ordering::AcqRel);
    if pending == 0 {
        return;
    }
    let mut out: Vec<(SessionTag, u32, String)> = Vec::new();
    {
        let ring = G_RING.lock();
        for index in 0..CAPACITY {
            if pending & (1u64 << index) == 0 {
                continue;
            }
            if let Some(entry) = ring.entries[index].as_ref() {
                if out.try_reserve(1).is_ok() {
                    if let Ok(path) = try_to_string(&entry.path) {
                        let _ = out.push_within_capacity((entry.session, entry.pid, path));
                    }
                }
            }
        }
    }
    for (session, pid, path) in out {
        emit(session, pid, path);
    }
}
