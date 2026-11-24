//! Mirage — decoys visible only to the agent (kernel half). A tagged process opening a sensitive
//! file for read has its file object name replaced with a decoy (`path` + a fixed suffix), so the
//! create is served from the decoy: the real secret never reaches the agent, while the human
//! (untagged) still reads the real file. The redirect is reported (`MirageRedirectEvent`) and the
//! existing canary channel is raised (`CanaryEvent`), so the client's canary alert fires.
//! `IoReplaceFileObjectName`/`FltSetCallbackDataDirty` are not in `km-api-sys`, so they are declared
//! here against the WDK ABI. Both are PASSIVE_LEVEL only; the pre-op normally is.
use alloc::{string::String, vec::Vec};

use ariadne::SessionTag;
use common::{
    event::{canary::CanaryEvent, mirage_redirect::MirageRedirectEvent, Event},
    utils::{try_extend, try_push_str, try_to_string},
};
use kernel_macros::NT_SUCCESS;
use km_api_sys::{flt_kernel::FLT_CALLBACK_DATA, wmd::KeGetCurrentIrql};
use winapi::shared::ntdef::{NTSTATUS, PVOID, USHORT};

use crate::{locked::Locked, send_message::send_message};

extern "system" {
    fn IoReplaceFileObjectName(
        file_object: PVOID,
        new_file_name: *const u16,
        file_name_length: USHORT,
    ) -> NTSTATUS;
    fn FltSetCallbackDataDirty(callback_data: *mut FLT_CALLBACK_DATA);
}

// sensitive files the agent tree must not read: path fragments joined by '\n', matched as
// case-insensitive substrings like the guardrail list. RAMON_MIRAGE_PATHS replaces them wholesale.
const DEFAULT_PATTERNS: &[&str] = &[r"\.aws\credentials", r"\.env", r"\.ssh\id_", r"\login data"];
// appended to the real path to name its decoy, which must exist on the same volume (same directory)
const DEFAULT_SUFFIX: &str = ".mirage";
// a decoy suffix is a short marker; the client config is capped to this many bytes
const MAX_SUFFIX: usize = 64;

struct Config {
    patterns: Vec<u8>,
    suffix: [u8; MAX_SUFFIX],
    suffix_len: usize,
    // paths and session roots where Mirage does not apply: a legal deploy needs the real credentials
    except_paths: Vec<u8>,
    except_sessions: Vec<(u32, u64)>,
}

static G_CONFIG: Locked<Config> = Locked::new(Config {
    patterns: Vec::new(),
    suffix: [0; MAX_SUFFIX],
    suffix_len: 0,
    except_paths: Vec::new(),
    except_sessions: Vec::new(),
});

/// Applies the built-in defaults at load, so decoys work before a client connects.
pub(crate) unsafe fn init() {
    G_CONFIG.init();
    {
        let mut config = G_CONFIG.lock();
        config.except_paths = Vec::new();
        config.except_sessions = Vec::new();
    }
    set(DEFAULT_PATTERNS.iter().copied(), DEFAULT_SUFFIX);
}

/// Replaces the exception lists: path fragments (substring match) and session roots (`pid:create_time`).
pub(crate) unsafe fn set_exceptions<'a>(
    paths: impl Iterator<Item = &'a str>,
    sessions: impl Iterator<Item = &'a str>,
) {
    // build outside the lock: allocation must not happen while holding it
    let paths = join_fragments(paths);
    let mut parsed: Vec<(u32, u64)> = Vec::new();
    for entry in sessions {
        if let Some((pid, create_time)) = entry.split_once(':') {
            if let (Ok(pid), Ok(create_time)) = (pid.parse::<u32>(), create_time.parse::<u64>()) {
                if parsed.try_reserve(1).is_ok() {
                    let _ = parsed.push_within_capacity((pid, create_time));
                }
            }
        }
    }
    let mut config = G_CONFIG.lock();
    config.except_paths = paths;
    config.except_sessions = parsed;
}

pub(crate) unsafe fn set<'a>(patterns: impl Iterator<Item = &'a str>, suffix: &str) {
    // build outside the lock: allocation must not happen while holding it
    let patterns = join_fragments(patterns);
    let bytes = suffix.as_bytes();
    // cap to the buffer, never splitting a UTF-8 sequence (so the stored suffix is always valid)
    let mut len = bytes.len().min(MAX_SUFFIX);
    while len > 0 && !suffix.is_char_boundary(len) {
        len -= 1;
    }
    let mut buf = [0u8; MAX_SUFFIX];
    buf[..len].copy_from_slice(&bytes[..len]);
    let mut config = G_CONFIG.lock();
    config.patterns = patterns;
    config.suffix = buf;
    config.suffix_len = len;
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

/// True when a tagged read of `name` must be redirected to a decoy. The pre-op calls this only for a
/// tagged read: a decoy itself never matches, and an exempt path or session reads the real file.
pub(crate) unsafe fn should_redirect(name: &str, session: SessionTag) -> bool {
    let config = G_CONFIG.lock();
    // a decoy is not a secret: the agent is meant to read it, and it must not match its own pattern
    if config.suffix_len != 0
        && ends_with_ignore_ascii_case(name.as_bytes(), &config.suffix[..config.suffix_len])
    {
        return false;
    }
    if !matches_any(&config.patterns, name) {
        return false;
    }
    if matches_any(&config.except_paths, name) {
        return false;
    }
    !config.except_sessions.iter().any(|(pid, create_time)| {
        session.root.pid == *pid && session.root.create_time == *create_time
    })
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

fn ends_with_ignore_ascii_case(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack.len() >= needle.len()
        && haystack[haystack.len() - needle.len()..].eq_ignore_ascii_case(needle)
}

// the decoy for `path` is `path` with the configured suffix appended (same directory, same volume,
// so the file object's device is still right); `None` when the suffix is empty or a copy fails
fn decoy_path(path: &str) -> Option<String> {
    // copy the suffix out of the lock: the allocation below must not run while holding it
    let (buf, len) = {
        let config = G_CONFIG.lock();
        (config.suffix, config.suffix_len)
    };
    if len == 0 {
        return None;
    }
    let suffix = core::str::from_utf8(&buf[..len]).ok()?;
    let mut decoy = try_to_string(path).ok()?;
    try_push_str(&mut decoy, suffix).ok()?;
    Some(decoy)
}

/// A tagged process asked to read `path`, which matches a Mirage pattern: replace the file object's
/// name with the decoy so the create is served from it. Reports the redirect and raises the canary.
/// Returns true when the name was replaced. `IoReplaceFileObjectName` is PASSIVE_LEVEL only.
pub(crate) unsafe fn redirect(
    data: &mut FLT_CALLBACK_DATA,
    file_object: PVOID,
    pid: u32,
    session: SessionTag,
    path: &str,
) -> bool {
    if u64::from(KeGetCurrentIrql()) > 0 {
        return false;
    }
    let Some(decoy) = decoy_path(path) else {
        return false;
    };
    // the new name is UTF-16 and not null-terminated: IoReplaceFileObjectName copies it and knows the
    // byte length. The buffer is ours and freed when it drops. A UTF-16 unit is at most 3 bytes of
    // UTF-8, so reserving `decoy.len()` units is always enough.
    let mut wide: Vec<u16> = Vec::new();
    if wide.try_reserve_exact(decoy.len()).is_err() {
        return false;
    }
    for unit in decoy.encode_utf16() {
        if wide.push_within_capacity(unit).is_err() {
            return false;
        }
    }
    let byte_len = wide.len() * 2;
    if byte_len > USHORT::MAX as usize {
        return false;
    }
    let status = IoReplaceFileObjectName(file_object, wide.as_ptr(), byte_len as USHORT);
    if !NT_SUCCESS!(status) {
        log::warn!("mirage: IoReplaceFileObjectName failed. Err: 0x{:08x}", status);
        return false;
    }
    // the create was redirected: tell FltMgr the callback data (and its cached name) changed
    FltSetCallbackDataDirty(data as *mut FLT_CALLBACK_DATA);
    emit(pid, session, path, &decoy);
    true
}

fn emit(pid: u32, session: SessionTag, path: &str, decoy: &str) {
    let (Ok(path), Ok(decoy)) = (try_to_string(path), try_to_string(decoy)) else {
        return;
    };
    let mirage = MirageRedirectEvent::new(pid, session, path, decoy);
    if let Ok(name) = try_to_string(mirage.path()) {
        // the canary channel reuses the existing alert: the agent touched a decoy it must not
        let canary = CanaryEvent::new(pid, session, name);
        send_message(canary.serialize().unwrap_or_default());
    }
    send_message(mirage.serialize().unwrap_or_default());
}
