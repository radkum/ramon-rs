//! NonPaged allocator for state that a callout may read at DISPATCH_LEVEL. The global allocator is
//! paged (kernel-alloc's default), so it cannot back the process tree: a page fault at DISPATCH
//! bugchecks. `ProcessTree::new_in` takes this as its `RawAlloc`, and it also implements
//! `core::alloc::Allocator` for `Box::try_new_in` / `Vec::new_in`.
use core::{
    alloc::{AllocError, Allocator, Layout},
    ptr::NonNull,
};

use kernel_btree::RawAlloc;
use km_api_sys::ntoskrnl::{ExAllocatePool2, ExFreePool, POOL_FLAG_NON_PAGED};
use winapi::shared::ntdef::PVOID;

// distinct from the paged TSUR tag, so the lab can track NonPaged pool by this tag alone
const NP_POOL_TAG: u32 = u32::from_ne_bytes(*b"RDNP");

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct NonPaged;

unsafe impl RawAlloc for NonPaged {
    fn alloc(&self, layout: Layout) -> *mut u8 {
        if layout.size() == 0 {
            return core::ptr::null_mut();
        }
        // ExAllocatePool2 zeroes the block; NON_PAGED may be allocated up to DISPATCH_LEVEL
        unsafe { ExAllocatePool2(POOL_FLAG_NON_PAGED, layout.size(), NP_POOL_TAG) as *mut u8 }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        unsafe { ExFreePool(ptr as PVOID) };
    }
}

unsafe impl Allocator for NonPaged {
    fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
        if layout.size() == 0 {
            // the contract requires a non-null, aligned dangling pointer for a zero-sized allocation
            let ptr = NonNull::new(layout.align() as *mut u8).ok_or(AllocError)?;
            return Ok(NonNull::slice_from_raw_parts(ptr, 0));
        }
        let ptr = NonNull::new(<Self as RawAlloc>::alloc(self, layout)).ok_or(AllocError)?;
        Ok(NonNull::slice_from_raw_parts(ptr, layout.size()))
    }

    unsafe fn deallocate(&self, ptr: NonNull<u8>, layout: Layout) {
        // `allocate` returns a dangling pointer for a zero-sized allocation: never free it
        if layout.size() == 0 {
            return;
        }
        unsafe { <Self as RawAlloc>::dealloc(self, ptr.as_ptr(), layout) };
    }
}
