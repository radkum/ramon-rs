//! Path protection: pre-create and pre-set-information deny writes, deletes and renames to a
//! configured list of paths. Two tiers: rules that apply only to the tagged process tree and
//! rules that apply to every process. The list is configured from user mode over the port.
//!
//! IRQL: PASSIVE_LEVEL in the pre-ops; no allocation on the allow path (the path is resolved
//! only when a rule could match).
#![allow(static_mut_refs)]

use alloc::vec::Vec;

use common::utils::try_extend;
use kernel_fast_mutex::{auto_lock::AutoLock, fast_mutex::FastMutex, locker::Locker};
use kernel_macros::HandleToU32;
use km_api_sys::{ntddk::PsGetCurrentProcessId, ntifs::PsGetCurrentProcess};
use winapi::{
    km::wdm::PEPROCESS,
    shared::ntdef::{BOOLEAN, PVOID},
};

// not declared in km-api-sys
extern "system" {
    fn PsReferencePrimaryToken(process: PEPROCESS) -> PVOID;
    fn PsDereferencePrimaryToken(token: PVOID);
    fn SeTokenIsAdmin(token: PVOID) -> BOOLEAN;
}

// the System process is always PID 4
const SYSTEM_PID: u32 = 4;

static mut G_MUTEX: FastMutex = FastMutex::new();
// path fragments that must not be modified, joined by '\n'. The tagged tier is refused only for a
// process with a session tag (the agent tree); the any tier is refused for every process. Both are
// replaced wholesale by the client's RAMON_GUARDRAIL_PATHS / RAMON_GUARDRAIL_ANY_PATHS.
static mut G_TAGGED: Vec<u8> = Vec::new();
static mut G_ANY: Vec<u8> = Vec::new();

// the agent's own settings and enterprise managed settings; settings.local.json is excluded on
// purpose (Claude Code writes it when a permission is approved)
const DEFAULT_TAGGED: &[&str] = &["\\.claude\\settings.json", "\\managed-settings.json"];

/// Applies the built-in defaults at load, so protection works before a client connects.
pub(crate) unsafe fn init() {
    // FAST_MUTEX::new() leaves Count = 0 (locked); acquiring an uninitialized mutex waits on a
    // zeroed event and bugchecks (0xA). Initialize it before the first lock.
    G_MUTEX.Init();
    set(DEFAULT_TAGGED.iter().copied(), core::iter::empty());
}

pub(crate) unsafe fn set<'a>(
    tagged: impl Iterator<Item = &'a str>,
    any: impl Iterator<Item = &'a str>,
) {
    // build outside the lock: allocation must not happen while holding it
    let tagged = join_fragments(tagged);
    let any = join_fragments(any);
    let _locker = AutoLock::new(&mut G_MUTEX);
    G_TAGGED = tagged;
    G_ANY = any;
}

// on allocation failure a fragment is dropped: the config is best-effort, never panics
fn join_fragments<'a>(fragments: impl Iterator<Item = &'a str>) -> Vec<u8> {
    let mut v = Vec::new();
    for fragment in fragments {
        let _ = try_extend(&mut v, fragment.as_bytes());
        let _ = try_extend(&mut v, b"\n");
    }
    v
}

pub(crate) unsafe fn is_protected_tagged(name: &str) -> bool {
    let _locker = AutoLock::new(&mut G_MUTEX);
    matches_any(&G_TAGGED, name)
}

/// True only when the any-process tier has fragments, so the pre-op can skip the name lookup.
pub(crate) unsafe fn any_active() -> bool {
    let _locker = AutoLock::new(&mut G_MUTEX);
    !G_ANY.is_empty()
}

pub(crate) unsafe fn is_protected_any(name: &str) -> bool {
    let _locker = AutoLock::new(&mut G_MUTEX);
    matches_any(&G_ANY, name)
}

fn matches_any(blob: &[u8], name: &str) -> bool {
    let haystack = name.as_bytes();
    blob.split(|byte| *byte == b'\n').any(|fragment| contains_ignore_ascii_case(haystack, fragment))
}

fn contains_ignore_ascii_case(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack.len() >= needle.len()
        && haystack.windows(needle.len()).any(|window| window.eq_ignore_ascii_case(needle))
}

/// True for SYSTEM and elevated administrators. The any-process tier exempts them: it guards a path
/// from unprivileged writers, not from the OS itself (blocking SYSTEM/admin would break installers,
/// GPO and services). The tagged tier is not exempt, so an elevated agent is still refused.
pub(crate) unsafe fn is_privileged() -> bool {
    if HandleToU32!(PsGetCurrentProcessId()) == SYSTEM_PID {
        return true;
    }
    let process = PsGetCurrentProcess();
    let token = PsReferencePrimaryToken(process);
    if token.is_null() {
        return false;
    }
    let admin = SeTokenIsAdmin(token) != 0;
    PsDereferencePrimaryToken(token);
    admin
}
