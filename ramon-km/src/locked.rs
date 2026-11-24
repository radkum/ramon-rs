//! `static` state without `static mut`.
//!
//! A [`Locked`] owns a `FAST_MUTEX` and its data. The data is reachable only through the guard
//! returned by [`Locked::lock`], and the guard releases the mutex when dropped, so only one
//! `&mut T` exists at a time. This keeps the `unsafe` in one place instead of at every call site
//! and removes the `static_mut_refs` allowance from the modules that use it.
//!
//! IRQL: `FAST_MUTEX` may only be acquired at IRQL <= APC_LEVEL. State read from a WFP callout at
//! DISPATCH_LEVEL uses `spinlock::SpinLocked` instead.
use core::{
    cell::UnsafeCell,
    ops::{Deref, DerefMut},
};

use km_api_sys::wmd::{ExAcquireFastMutex, ExInitializeFastMutex, ExReleaseFastMutex, FAST_MUTEX};

pub(crate) struct Locked<T> {
    lock: UnsafeCell<FAST_MUTEX>,
    data: UnsafeCell<T>,
}

// SAFETY: every access to `data` goes through `lock()`, which holds the mutex for the lifetime of
// the guard; the mutex itself is only touched by the acquire/release calls.
unsafe impl<T: Send> Sync for Locked<T> {}

impl<T> Locked<T> {
    pub(crate) const fn new(data: T) -> Self {
        Self { lock: UnsafeCell::new(FAST_MUTEX::new()), data: UnsafeCell::new(data) }
    }

    /// Initializes the mutex. Call once at PASSIVE_LEVEL before any callback can lock it:
    /// a zeroed `FAST_MUTEX` is "locked" and acquiring it bugchecks (0xA).
    ///
    /// # Safety
    /// Must be called exactly once, before any other thread can reach this value.
    pub(crate) unsafe fn init(&self) {
        ExInitializeFastMutex(&mut *self.lock.get())
    }

    pub(crate) fn lock(&self) -> LockedGuard<'_, T> {
        let lock = self.lock.get();
        // SAFETY: the guard holds the mutex until it is dropped, and a second `lock()` blocks in
        // `ExAcquireFastMutex` before it can form its own reference, so the `&mut T` is unique.
        unsafe {
            ExAcquireFastMutex(lock);
            LockedGuard { data: &mut *self.data.get(), lock }
        }
    }
}

/// Exclusive access to the data of a [`Locked`]; releases the mutex when dropped.
pub(crate) struct LockedGuard<'a, T> {
    data: &'a mut T,
    lock: *mut FAST_MUTEX,
}

impl<T> Deref for LockedGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        self.data
    }
}

impl<T> DerefMut for LockedGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        self.data
    }
}

impl<T> Drop for LockedGuard<'_, T> {
    fn drop(&mut self) {
        unsafe { ExReleaseFastMutex(self.lock) }
    }
}
