//! MOTA — Mark-of-the-Agent (kernel half). A file created or written by an agent process gets a
//! stream context (the in-cache marker) and is remembered by FileId (survives handle close within a
//! boot). When a process outside the agent tree opens a marked file, the delayed execution is
//! reported. The `Flt*Context` and `FltQueryInformationFile` APIs are not in `km-api-sys`, so they are
//! declared here against the WDK ABI.
use alloc::string::String;
use core::{
    mem::size_of,
    ptr::null_mut,
    sync::atomic::{AtomicU32, Ordering},
};

use ariadne::SessionTag;
use common::event::{
    mota::{FileId, MotaEvent, MOTA_HIT, MOTA_MARK},
    Event,
};
use kernel_macros::NT_SUCCESS;
use km_api_sys::{
    constants::APC_LEVEL,
    flt_kernel::{FLT_RELATED_OBJECTS, PFLT_FILTER, PFLT_INSTANCE},
    ntifs::PsGetCurrentProcess,
    wmd::KeGetCurrentIrql,
};
use winapi::{
    km::wdm::PEPROCESS,
    shared::ntdef::{NTSTATUS, PVOID},
};

use crate::{locked::Locked, send_message::send_message};

// FLT_CONTEXT_TYPE / FLT_CONTEXT_END (fltKernel.h)
const FLT_STREAM_CONTEXT: u16 = 0x0008;
const FLT_CONTEXT_END: u16 = 0xffff;
// FLT_SET_CONTEXT_OPERATION
const FLT_SET_CONTEXT_KEEP_IF_EXISTS: i32 = 1;
// FILE_INFORMATION_CLASS::FileIdInformation
const FILE_ID_INFORMATION_CLASS: i32 = 59;

extern "system" {
    fn FltAllocateContext(
        filter: PFLT_FILTER,
        context_type: u16,
        context_size: usize,
        pool_type: u32,
        returned_context: *mut PVOID,
    ) -> NTSTATUS;
    fn FltSetStreamContext(
        instance: PFLT_INSTANCE,
        file_object: PVOID,
        operation: i32,
        new_context: PVOID,
        old_context: *mut PVOID,
    ) -> NTSTATUS;
    fn FltGetStreamContext(
        instance: PFLT_INSTANCE,
        file_object: PVOID,
        context: *mut PVOID,
    ) -> NTSTATUS;
    fn FltReleaseContext(context: PVOID);
    fn FltQueryInformationFile(
        instance: PFLT_INSTANCE,
        file_object: PVOID,
        file_information: PVOID,
        length: u32,
        file_information_class: i32,
        length_returned: *mut u32,
    ) -> NTSTATUS;
    fn PsGetProcessImageFileName(process: PEPROCESS) -> *const u8;
}

// EPROCESS.ImageFileName is 15 bytes and not NUL-terminated when full
const IMAGE_FILE_NAME_LEN: usize = 15;

/// Image name of the current (opening) process: the client dedups HITs on `(path, image)` across its
/// restarts. Empty when the name cannot be read (the client then falls back to a per-path key).
unsafe fn current_image() -> String {
    let name = PsGetProcessImageFileName(PsGetCurrentProcess());
    if name.is_null() {
        return String::new();
    }
    let bytes = core::slice::from_raw_parts(name, IMAGE_FILE_NAME_LEN);
    let len = bytes.iter().position(|b| *b == 0).unwrap_or(IMAGE_FILE_NAME_LEN);
    let mut buffer = alloc::vec::Vec::new();
    if common::utils::try_extend(&mut buffer, &bytes[..len]).is_err() {
        return String::new();
    }
    String::from_utf8(buffer).unwrap_or_default()
}

/// The marker a stream carries: the agent session that authored the file.
#[repr(C)]
struct MotaContext {
    session: SessionTag,
}

/// `FILE_ID_INFORMATION`: the volume serial and 128-bit file id.
#[repr(C)]
struct FileIdInformation {
    volume_serial_number: u64,
    file_id: [u8; 16],
}

#[repr(C)]
pub(crate) struct FltContextRegistration {
    context_type: u16,
    flags: u16,
    cleanup: PVOID,
    size: usize,
    pool_tag: u32,
    allocate: PVOID,
    free: PVOID,
    reserved: PVOID,
}

const fn no_context(context_type: u16, size: usize, pool_tag: u32) -> FltContextRegistration {
    FltContextRegistration {
        context_type,
        flags: 0,
        cleanup: null_mut(),
        size,
        pool_tag,
        allocate: null_mut(),
        free: null_mut(),
        reserved: null_mut(),
    }
}

/// Registered in `FLT_REGISTRATION.ContextRegistration`; the `FLT_CONTEXT_END` entry terminates it and
/// must be all-zero except for its type (`FLT_STREAM_CONTEXT` itself needs a non-zero pool tag).
pub(crate) const CONTEXT_REGISTRATION: &[FltContextRegistration] = &[
    no_context(FLT_STREAM_CONTEXT, size_of::<MotaContext>(), u32::from_ne_bytes(*b"ramM")),
    no_context(FLT_CONTEXT_END, 0, 0),
];

// extensions whose later execution is worth a per-open FileId lookup (scripts/installers; not .exe/.dll,
// which are opened constantly, nor extensionless files, too many to query)
const WATCH_EXTENSIONS: &[&str] = &[
    "ps1", "psm1", "psd1", "bat", "cmd", "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta", "sh",
    "py", "rb", "pl", "php", "reg", "lnk", "com", "scr", "msi", "jar",
];

fn watch_extension(extension: Option<&str>) -> bool {
    extension.is_some_and(|extension| {
        WATCH_EXTENSIONS.iter().any(|wanted| extension.eq_ignore_ascii_case(wanted))
    })
}

// Paths whose later opening is pure noise: the tagged tree authors them, but they are tool runtime /
// dependency installs, not agent content. `__psscriptpolicytest_` and `ps-script-` are PowerShell's own
// temp scripts; `node_modules`/`site-packages`/`.cache` and the PowerShell module dirs are the tool's
// runtime and installed dependencies (OpenCode rewrites its own `node_modules`, `Install-Module` writes
// the module tree). Marking them turns normal work into a flood of delayed-execution hits.
const DENY_FRAGMENTS: &[&str] = &[
    "__psscriptpolicytest_",
    "\\node_modules\\",
    "\\site-packages\\",
    "\\.cache\\",
    "powershell\\modules\\",
    "ps-script-",
];

fn contains_ignore_ascii_case(haystack: &str, needle: &str) -> bool {
    let (haystack, needle) = (haystack.as_bytes(), needle.as_bytes());
    !needle.is_empty()
        && needle.len() <= haystack.len()
        && haystack.windows(needle.len()).any(|window| window.eq_ignore_ascii_case(needle))
}

fn denied(path: &str) -> bool {
    DENY_FRAGMENTS.iter().any(|fragment| contains_ignore_ascii_case(path, fragment))
}

/// A watched file: a script/installer extension, or an extensionless path under a `hooks` directory
/// (git hooks) or anywhere in a `.git` tree (git hooks and other extensionless executables), which the
/// extension list alone would miss. Denylisted paths (tool runtime, dependency installs, PowerShell
/// temp scripts) are never watched, so they are neither marked nor hit.
pub(crate) fn watch_path(path: &str, extension: Option<&str>) -> bool {
    if denied(path) {
        return false;
    }
    watch_extension(extension)
        || (extension.is_none() && (contains_ignore_ascii_case(path, r"\hooks\")))
        || (extension.is_none() && contains_ignore_ascii_case(path, r"\.git\"))
}

// FileId -> authoring session, remembered so the marker survives the agent closing the file. Keyed by
// FileId alone: it is stable across a rename/move, and a delete removes the entry, so a FileId NTFS
// later reuses for an unrelated file finds nothing. A fixed ring: bounded and allocation-free (the
// driver must not fault on OOM).
const CAPACITY: usize = 4096;

struct Marks {
    ring: [Option<(FileId, SessionTag)>; CAPACITY],
    next: usize,
}

static G_MARKS: Locked<Marks> = Locked::new(Marks { ring: [None; CAPACITY], next: 0 });
// the connected client scans agent-authored files; its own opens must not count as a hit
static G_CLIENT_PID: AtomicU32 = AtomicU32::new(0);

pub(crate) unsafe fn init() {
    G_MARKS.init();
    {
        let mut marks = G_MARKS.lock();
        marks.ring = [None; CAPACITY];
        marks.next = 0;
    }
    G_CLIENT_PID.store(0, Ordering::Release);
}

pub(crate) unsafe fn set_client_pid(pid: u32) {
    G_CLIENT_PID.store(pid, Ordering::Release);
}

/// Loads one marker the client kept on disk (survives a reboot); the driver's ring is rebuilt on
/// client start.
pub(crate) fn load_entry(file_id: FileId, session: SessionTag, path: &str) {
    if denied(path) {
        return;
    }
    remember(file_id, session);
}

/// Drops the marker of a file that is being deleted, so a reused FileId is not a false hit.
pub(crate) unsafe fn forget_file(flt_objects: &FLT_RELATED_OBJECTS) {
    if u64::from(KeGetCurrentIrql()) > APC_LEVEL {
        return;
    }
    if let Some(file_id) = query_file_id(flt_objects.Instance, flt_objects.FileObject as PVOID) {
        forget(file_id);
    }
}

fn remember(file_id: FileId, session: SessionTag) {
    let mut marks = G_MARKS.lock();
    for entry in marks.ring.iter_mut() {
        if entry.is_some_and(|(id, _)| id == file_id) {
            *entry = Some((file_id, session));
            return;
        }
    }
    let index = marks.next;
    marks.ring[index] = Some((file_id, session));
    marks.next = (index + 1) % CAPACITY;
}

fn recall(file_id: FileId) -> Option<SessionTag> {
    let marks = G_MARKS.lock();
    marks.ring.iter().flatten().find(|(id, _)| *id == file_id).map(|(_, session)| *session)
}

// the marked file was deleted: drop the marker, so a FileId NTFS reuses later is not a false hit
fn forget(file_id: FileId) {
    let mut marks = G_MARKS.lock();
    for entry in marks.ring.iter_mut() {
        if entry.is_some_and(|(id, _)| id == file_id) {
            *entry = None;
            return;
        }
    }
}

fn query_file_id(instance: PFLT_INSTANCE, file_object: PVOID) -> Option<FileId> {
    // FltQueryInformationFile is PASSIVE_LEVEL only; a post-create normally is, but do not risk it
    if u64::from(unsafe { KeGetCurrentIrql() }) > 0 {
        return None;
    }
    let mut info = FileIdInformation { volume_serial_number: 0, file_id: [0; 16] };
    let mut returned = 0u32;
    let status = unsafe {
        FltQueryInformationFile(
            instance,
            file_object,
            &mut info as *mut FileIdInformation as PVOID,
            size_of::<FileIdInformation>() as u32,
            FILE_ID_INFORMATION_CLASS,
            &mut returned,
        )
    };
    NT_SUCCESS!(status).then_some(FileId { volume: info.volume_serial_number, id: info.file_id })
}

// FltAllocateContext + FltSetStreamContext: our reference is always released; on success the stream
// holds its own, on KEEP_IF_EXISTS the existing context is returned in `old` and released here too
fn set_stream_context(
    filter: PFLT_FILTER,
    instance: PFLT_INSTANCE,
    file_object: PVOID,
    session: SessionTag,
) {
    let mut context: PVOID = null_mut();
    let status = unsafe {
        FltAllocateContext(
            filter,
            FLT_STREAM_CONTEXT,
            size_of::<MotaContext>(),
            0, // NonPagedPool
            &mut context,
        )
    };
    if !NT_SUCCESS!(status) || context.is_null() {
        return;
    }
    unsafe { (*(context as *mut MotaContext)).session = session };
    let mut old: PVOID = null_mut();
    unsafe {
        FltSetStreamContext(
            instance,
            file_object,
            FLT_SET_CONTEXT_KEEP_IF_EXISTS,
            context,
            &mut old,
        );
        FltReleaseContext(context);
        if !old.is_null() {
            FltReleaseContext(old);
        }
    }
}

fn stream_context_session(instance: PFLT_INSTANCE, file_object: PVOID) -> Option<SessionTag> {
    let mut context: PVOID = null_mut();
    let status = unsafe { FltGetStreamContext(instance, file_object, &mut context) };
    if !NT_SUCCESS!(status) || context.is_null() {
        return None;
    }
    let session = unsafe { (*(context as *const MotaContext)).session };
    unsafe { FltReleaseContext(context) };
    Some(session)
}

fn emit(kind: u8, pid: u32, session: SessionTag, file_id: FileId, path: &str, image: &str) {
    if let Ok(name) = common::utils::try_to_string(path) {
        let image = common::utils::try_to_string(image).unwrap_or_default();
        let event = MotaEvent::new(pid, kind, session, file_id, name, image);
        send_message(event.serialize().unwrap_or_default());
    }
}

/// A tagged process authored `path`: set the stream context and remember the FileId.
pub(crate) unsafe fn mark(
    flt_objects: &FLT_RELATED_OBJECTS,
    pid: u32,
    session: SessionTag,
    path: &str,
) {
    // FltAllocateContext/FltSetStreamContext are APC_LEVEL max; a post-create normally is PASSIVE
    if u64::from(KeGetCurrentIrql()) > APC_LEVEL || denied(path) {
        return;
    }
    let file_object = flt_objects.FileObject as PVOID;
    set_stream_context(flt_objects.Filter, flt_objects.Instance, file_object, session);
    if let Some(file_id) = query_file_id(flt_objects.Instance, file_object) {
        remember(file_id, session);
        emit(MOTA_MARK, pid, session, file_id, path, "");
    }
}

/// An untagged process opened `path`: report a hit if the file carries Mark-of-the-Agent. The stream
/// context is the cheap path; the FileId ring covers a file the agent has already closed. The ring is
/// only consulted for watched extensions, to bound the per-open lookup.
pub(crate) unsafe fn check(
    flt_objects: &FLT_RELATED_OBJECTS,
    pid: u32,
    path: &str,
    extension: Option<&str>,
) -> bool {
    if u64::from(KeGetCurrentIrql()) > APC_LEVEL || pid == G_CLIENT_PID.load(Ordering::Acquire) {
        return false;
    }
    // only watched paths are ever marked (see file_monitor), so a non-watched open has nothing to
    // find: skip the context lookup and the FileId query, which would otherwise run on every open
    if !watch_path(path, extension) {
        return false;
    }
    let file_object = flt_objects.FileObject as PVOID;
    let image = current_image();
    if let Some(session) = stream_context_session(flt_objects.Instance, file_object) {
        let file_id = query_file_id(flt_objects.Instance, file_object)
            .unwrap_or(FileId { volume: 0, id: [0; 16] });
        emit(MOTA_HIT, pid, session, file_id, path, &image);
        return true;
    }
    if let Some(file_id) = query_file_id(flt_objects.Instance, file_object) {
        if let Some(session) = recall(file_id) {
            emit(MOTA_HIT, pid, session, file_id, path, &image);
            return true;
        }
    }
    false
}
