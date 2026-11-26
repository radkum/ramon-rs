//! Create handoff: `RamonPreCreate` hands the name it already resolved (for the guardrail or
//! mirage) to `RamonPostCreate` through the pre-op completion context, so a tagged create resolves
//! the name once instead of twice. The box is owned by the operation: the post-op frees it on every
//! path. No per-file-object state is kept, so a burst of creates adds no persistent pool.
use alloc::{boxed::Box, string::String};
use core::ptr::null_mut;

use winapi::shared::ntdef::PVOID;

/// The resolved name handed from pre-create to post-create.
pub(crate) struct PathInfo {
    pub guid: String,
    pub ext: Option<String>,
}

/// Boxes the resolved name for the pre-op completion context; null on allocation failure (the
/// post-op then resolves it again).
pub(crate) fn into_completion(name: (String, Option<String>)) -> PVOID {
    let (guid, ext) = name;
    match Box::try_new(PathInfo { guid, ext }) {
        Ok(boxed) => Box::into_raw(boxed) as PVOID,
        Err(_) => null_mut(),
    }
}

/// Takes ownership of the completion context set by [`into_completion`].
pub(crate) unsafe fn take_completion(context: PVOID) -> Option<PathInfo> {
    if context.is_null() {
        return None;
    }
    Some(*Box::from_raw(context as *mut PathInfo))
}
