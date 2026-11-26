//! A spinlock that owns its state, so state read from a callout at DISPATCH_LEVEL is protected without
//! the FAST_MUTEX (which may only be acquired at IRQL <= APC_LEVEL). `KSPIN_LOCK` is a `ULONG_PTR`,
//! zeroed when unlocked, so a zero-initialized static is already valid.

use core::cell::UnsafeCell;

// not declared in km-api-sys
extern "system" {
    fn KeInitializeSpinLock(spin_lock: *mut usize);
    // raises IRQL to DISPATCH and returns the previous IRQL
    fn KeAcquireSpinLockRaiseToDpc(spin_lock: *mut usize) -> u8;
    fn KeReleaseSpinLock(spin_lock: *mut usize, new_irql: u8);
}

/// A spinlock together with the state it protects: the state is reachable only through the guard,
/// which restores the previous IRQL when dropped. Use for state read at DISPATCH_LEVEL.
pub(crate) struct SpinLocked<T> {
    lock: UnsafeCell<usize>,
    data: UnsafeCell<T>,
}

// SAFETY: every access to `data` goes through `lock()`, and the spinlock raises IRQL to DISPATCH,
// so only one `&mut T` can exist at a time.
unsafe impl<T> Sync for SpinLocked<T> {}

impl<T> SpinLocked<T> {
    pub(crate) const fn new(data: T) -> Self {
        Self { lock: UnsafeCell::new(0), data: UnsafeCell::new(data) }
    }

    pub(crate) fn init(&self) {
        unsafe { KeInitializeSpinLock(self.lock.get()) };
    }

    /// The address of the protected state, for code that must not take the lock (a pointer handed
    /// to the OS, or an event waited on outside the lock). Taking the lock gives the same address.
    pub(crate) fn get_ptr(&self) -> *mut T {
        self.data.get()
    }

    pub(crate) fn lock(&self) -> SpinLockedGuard<'_, T> {
        unsafe {
            let irql = KeAcquireSpinLockRaiseToDpc(self.lock.get());
            SpinLockedGuard { data: &mut *self.data.get(), lock: self.lock.get(), irql }
        }
    }
}

/// Exclusive access to the data of a [`SpinLocked`]; releases the spinlock when dropped.
pub(crate) struct SpinLockedGuard<'a, T> {
    data: &'a mut T,
    lock: *mut usize,
    irql: u8,
}

impl<T> core::ops::Deref for SpinLockedGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        self.data
    }
}

impl<T> core::ops::DerefMut for SpinLockedGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        self.data
    }
}

impl<T> Drop for SpinLockedGuard<'_, T> {
    fn drop(&mut self) {
        unsafe { KeReleaseSpinLock(self.lock, self.irql) };
    }
}
