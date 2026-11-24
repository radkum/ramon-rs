//! A minimal spinlock, so state read from a callout at DISPATCH_LEVEL can be protected without the
//! FAST_MUTEX (which may only be acquired at IRQL <= APC_LEVEL). `KSPIN_LOCK` is a `ULONG_PTR`, zeroed
//! when unlocked, so a zero-initialized static is already valid; `init` is kept for symmetry.
#![allow(static_mut_refs)]

// not declared in km-api-sys
extern "system" {
    fn KeInitializeSpinLock(spin_lock: *mut usize);
    // raises IRQL to DISPATCH and returns the previous IRQL
    fn KeAcquireSpinLockRaiseToDpc(spin_lock: *mut usize) -> u8;
    fn KeReleaseSpinLock(spin_lock: *mut usize, new_irql: u8);
}

/// A kernel spinlock. Use [`SpinLock::lock`]; the returned guard releases on drop.
pub(crate) struct SpinLock(usize);

impl SpinLock {
    pub(crate) const fn new() -> Self {
        Self(0)
    }

    pub(crate) fn init(&mut self) {
        unsafe { KeInitializeSpinLock(&mut self.0) };
    }

    /// # Safety
    /// The lock must outlive the guard; the caller must not block or page-fault while it is held.
    pub(crate) unsafe fn lock(&mut self) -> SpinGuard {
        let irql = KeAcquireSpinLockRaiseToDpc(&mut self.0);
        SpinGuard { lock: &mut self.0 as *mut usize, irql }
    }
}

/// Releases the spinlock when dropped.
pub(crate) struct SpinGuard {
    lock: *mut usize,
    irql: u8,
}

impl Drop for SpinGuard {
    fn drop(&mut self) {
        unsafe { KeReleaseSpinLock(self.lock, self.irql) };
    }
}
