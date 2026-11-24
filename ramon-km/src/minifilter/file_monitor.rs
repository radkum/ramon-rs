//! File callbacks: post-create (creates, delete-on-close), write post-op, set-information
//! (delete/rename) and the section-synchronization pair used for memory-mapped writes.
//!
//! IRQL: post-create and set-information run at PASSIVE_LEVEL; the write and section post-ops
//! can run at DISPATCH_LEVEL (paging I/O) - those paths only touch atomics and hand the report
//! to a PASSIVE_LEVEL drain (`section_sync::drain_written`).
use alloc::string::String;
use core::{mem::ManuallyDrop, ptr::null_mut};

use ariadne::SessionTag;
use common::{
    event::{
        canary::CanaryEvent,
        file_set_information::{FileSetInformationEvent, KIND_DELETE, KIND_RENAME},
        file_telemetry::{INTENT_READ, INTENT_WRITE},
        guardrail_blocked::{
            GuardrailBlockedEvent, KIND_DELETE as GRB_DELETE, KIND_RENAME as GRB_RENAME,
            KIND_WRITE as GRB_WRITE,
        },
        Event, FileCreateEvent, FileTelemetryEvent,
    },
    utils::{try_filled, try_push_str, try_to_string},
};
use kernel_macros::{HandleToU32, NT_SUCCESS};
use kernel_string::{PUNICODE_STRING, UNICODE_STRING};
use km_api_sys::{
    flt_kernel::{
        FltGetFileNameInformation, FltGetVolumeFromFileObject, FltGetVolumeGuidName,
        FltIsDirectory, FltParseFileNameInformation, FltReleaseFileNameInformation,
        FILE_INFORMATION_CLASS, FLT_CALLBACK_DATA, FLT_FILE_NAME_OPTIONS,
        FLT_POSTOP_CALLBACK_STATUS,
        FLT_POSTOP_CALLBACK_STATUS::FLT_POSTOP_FINISHED_PROCESSING,
        FLT_POST_OPERATION_FLAGS, FLT_PREOP_CALLBACK_STATUS,
        FLT_PREOP_CALLBACK_STATUS::{
            FLT_PREOP_COMPLETE, FLT_PREOP_SUCCESS_NO_CALLBACK, FLT_PREOP_SUCCESS_WITH_CALLBACK,
        },
        FLT_RELATED_OBJECTS, PFLT_FILE_NAME_INFORMATION, PFLT_INSTANCE,
    },
    ntddk::PsGetCurrentProcessId,
    wmd::{KeGetCurrentIrql, APC_LEVEL},
};
use winapi::{
    km::wdm::{
        FILE_APPEND_DATA, FILE_READ_DATA, FILE_WRITE_DATA, GENERIC_READ, GENERIC_WRITE,
        KPROCESSOR_MODE,
    },
    shared::{
        ntdef::{BOOLEAN, NTSTATUS, PVOID, TRUE, ULONG},
        ntstatus::{STATUS_ACCESS_DENIED, STATUS_REPARSE},
    },
};

use crate::{guardrail, notifiers::session_tag_of, send_message::send_message};

// not declared in km-api-sys
extern "system" {
    fn FltObjectDereference(flt_object: PVOID);
    fn FltGetFileNameInformationUnsafe(
        file_object: PVOID,
        instance: PFLT_INSTANCE,
        name_options: FLT_FILE_NAME_OPTIONS,
        file_name_information: *mut PFLT_FILE_NAME_INFORMATION,
    ) -> NTSTATUS;
}
const FLTFL_POST_OPERATION_DRAINING: FLT_POST_OPERATION_FLAGS = 0x1;
// None reports every successful open (what MOTA needs), at many times the event volume
const REPORTED_EXTENSION: Option<&str> = Some("exe");
// FileTelemetry is for content worth grepping; image loads often request write-like access.
const TELEMETRY_EXTENSIONS: &[&str] = &[
    "txt",
    "md",
    "json",
    "jsonl",
    "html",
    "htm",
    "js",
    "ts",
    "ps1",
    "psm1",
    "psd1",
    "xml",
    "yaml",
    "yml",
    "csv",
    "log",
    "ini",
    "cfg",
    "conf",
    "env",
    "toml",
    "properties",
    "bat",
    "cmd",
    "sh",
    "py",
    "rb",
    "pl",
    "php",
    "sql",
    "reg",
    "vbs",
    "hta",
    "pem",
    "key",
    "crt",
    "cer",
];
// decoy files: any open by a tagged process is a tripwire hit, whatever the intent
const CANARY_EXTENSION: &str = "canary";

#[repr(C)]
struct IoSecurityContext {
    security_qos: PVOID,
    access_state: PVOID,
    desired_access: ULONG,
    full_create_options: ULONG,
}

// FLT_PARAMETERS.AcquireForSectionSynchronization (not in km-api-sys); the union is at offset 0, so the
// callback data's Parameters can be overlaid with this struct. `SyncType` is FS_FILTER_SECTION_SYNC_TYPE.
#[repr(C)]
struct AcquireForSectionSynchronization {
    sync_type: u32,
    page_protection: u32,
    output_information: PVOID,
    flags: u32,
    allocation_attributes: u32,
}
const SYNC_TYPE_CREATE_SECTION: u32 = 1;
// PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
const PAGE_WRITABLE: u32 = 0x04 | 0x08 | 0x40 | 0x80;

pub(crate) struct FileMonitor {}
impl FileMonitor {
    /*************************************************************************
    MiniFilter callback routines.
    *************************************************************************/
    // guardrail integrity: the agent must never edit its own config. Refuse an open that would
    // write or delete a protected path. Pre-op, so it must stay cheap: tag first, then intent, then name.
    pub(crate) extern "system" fn RamonPreCreate(
        data: &mut FLT_CALLBACK_DATA,
        flt_objects: &mut FLT_RELATED_OBJECTS,
        _completion_context: *mut PVOID,
    ) -> FLT_PREOP_CALLBACK_STATUS {
        // a kernel create (paging I/O, our own I/O) is never the agent's
        if let KPROCESSOR_MODE::KernelMode = data.RequestorMode {
            return FLT_PREOP_SUCCESS_WITH_CALLBACK;
        }
        let delete = delete_on_close(data);
        let access = desired_access(data);
        let write = access & (FILE_WRITE_DATA | FILE_APPEND_DATA | GENERIC_WRITE) != 0;
        let read = access & (FILE_READ_DATA | GENERIC_READ) != 0;
        if !delete && !write && !read {
            return FLT_PREOP_SUCCESS_WITH_CALLBACK;
        }
        let pid = HandleToU32!(unsafe { PsGetCurrentProcessId() });
        let session = unsafe { session_tag_of(pid) };
        // guardrail (write/delete) applies to a tagged process or, for the any tier, to any process;
        // mirage (read) applies to a tagged process only. Resolve the name once when either needs it.
        let guardrail_needed =
            (delete || write) && (session.is_some() || unsafe { guardrail::any_active() });
        let mirage_needed = read && !delete && session.is_some();
        if !guardrail_needed && !mirage_needed {
            return FLT_PREOP_SUCCESS_WITH_CALLBACK;
        }
        let Some((file_name, device_name, _)) = file_path(data, flt_objects) else {
            return FLT_PREOP_SUCCESS_WITH_CALLBACK;
        };
        // guardrail: the agent must never edit its own config; the any tier never refuses SYSTEM/admin
        if guardrail_needed {
            let protected = match session {
                Some(_) => unsafe { guardrail::is_protected_tagged(&file_name) },
                None => unsafe { guardrail::is_protected_any(&file_name) },
            };
            if protected && !(session.is_none() && unsafe { guardrail::is_privileged() }) {
                let kind = if delete { GRB_DELETE } else { GRB_WRITE };
                block_guardrail(data, pid, session, kind, &file_name);
                return FLT_PREOP_COMPLETE;
            }
        }
        // Mirage: a tagged read of a sensitive file is served a decoy. If the redirect cannot be
        // applied the open is refused rather than serving the real secret (fail closed).
        if mirage_needed {
            if let Some(session) = session {
                if unsafe { crate::mirage::should_redirect(&device_name, session) } {
                    let redirected = unsafe {
                        crate::mirage::redirect(
                            data,
                            flt_objects.FileObject as PVOID,
                            pid,
                            session,
                            &device_name,
                        )
                    };
                    if !redirected {
                        unsafe {
                            *data.IoStatus.__bindgen_anon_1.Status_mut() = STATUS_ACCESS_DENIED;
                        }
                        return FLT_PREOP_COMPLETE;
                    }
                }
            }
        }
        FLT_PREOP_SUCCESS_WITH_CALLBACK
    }

    pub(crate) extern "system" fn RamonPostCreate(
        data: &mut FLT_CALLBACK_DATA,
        flt_objects: &mut FLT_RELATED_OBJECTS,
        _completion_context: PVOID,
        flags: FLT_POST_OPERATION_FLAGS,
    ) -> FLT_POSTOP_CALLBACK_STATUS {
        let mut ntstatus = unsafe { data.IoStatus.__bindgen_anon_1.Status().clone() };
        // the file was not opened, or the instance is being torn down
        if !NT_SUCCESS!(ntstatus)
            || ntstatus == STATUS_REPARSE
            || flags & FLTFL_POST_OPERATION_DRAINING != 0
        {
            return FLT_POSTOP_FINISHED_PROCESSING;
        }

        // skip if dir is created
        let mut is_dir: BOOLEAN = 0;
        ntstatus = unsafe { FltIsDirectory(flt_objects.Filter, flt_objects.Instance, &mut is_dir) };

        if NT_SUCCESS!(ntstatus) && is_dir == TRUE {
            log::info!("Skip directory");
            return FLT_POSTOP_FINISHED_PROCESSING;
        }

        if flt_objects.FileObject.is_null() {
            log::warn!("FileObject is null");
            return FLT_POSTOP_FINISHED_PROCESSING;
        }

        let Some((file_name, _device, extension)) = file_path(data, flt_objects) else {
            return FLT_POSTOP_FINISHED_PROCESSING;
        };
        let pid = HandleToU32!(unsafe { PsGetCurrentProcessId() });
        // MOTA: a tagged process writing a watched file marks it; an untagged process opening a marked
        // file is delayed execution (the agent authored content that someone else now runs). A
        // kernel-mode create (paging I/O, a system scan) is never the agent or a user.
        if let KPROCESSOR_MODE::UserMode = data.RequestorMode {
            match unsafe { session_tag_of(pid) } {
                Some(session)
                    if telemetry_intent(data) == Some(INTENT_WRITE)
                        && crate::mota::watch_path(&file_name, extension.as_deref()) =>
                {
                    unsafe { crate::mota::mark(flt_objects, pid, session, &file_name) };
                },
                None => unsafe {
                    crate::mota::check(flt_objects, pid, &file_name, extension.as_deref());
                },
                _ => {},
            }
        }
        if telemetry_extension(extension.as_deref()) {
            if let Some(intent) = telemetry_intent(data) {
                if let Some(session) = unsafe { session_tag_of(pid) } {
                    if let Ok(telemetry_name) = try_to_string(&file_name) {
                        FileMonitor::ProcessFileTelemetryEvent(
                            pid,
                            session,
                            intent,
                            telemetry_name,
                        );
                    }
                }
            }
        }

        if canary_extension(extension.as_deref()) {
            if let Some(session) = unsafe { session_tag_of(pid) } {
                if let Ok(canary_name) = try_to_string(&file_name) {
                    FileMonitor::ProcessCanaryEvent(pid, session, canary_name);
                }
            }
        }

        if delete_on_close(data) {
            // the file is deleted on close: drop its MOTA marker, whatever the process
            unsafe { crate::mota::forget_file(flt_objects) };
            if let Some(session) = unsafe { session_tag_of(pid) } {
                if let Ok(name) = try_to_string(&file_name) {
                    FileMonitor::ProcessFileSetInformationEvent(pid, session, KIND_DELETE, name);
                }
            }
        }

        let reported = match REPORTED_EXTENSION {
            None => true,
            Some(reported) => extension.is_some_and(|e| e.eq_ignore_ascii_case(reported)),
        };
        if reported {
            FileMonitor::ProcessFileEvent(file_name);
        }

        FLT_POSTOP_FINISHED_PROCESSING
    }

    // a write can complete at DISPATCH_LEVEL (paging I/O) in a system thread: only a passive, tagged write is ours
    pub(crate) extern "system" fn RamonPostWrite(
        data: &mut FLT_CALLBACK_DATA,
        flt_objects: &mut FLT_RELATED_OBJECTS,
        _completion_context: PVOID,
        flags: FLT_POST_OPERATION_FLAGS,
    ) -> FLT_POSTOP_CALLBACK_STATUS {
        if flags & FLTFL_POST_OPERATION_DRAINING != 0 {
            return FLT_POSTOP_FINISHED_PROCESSING;
        }
        let ntstatus = unsafe { data.IoStatus.__bindgen_anon_1.Status().clone() };
        let irql = u64::from(unsafe { KeGetCurrentIrql() });
        // a paging write (memory-mapped writeback) runs in a system thread, often at DISPATCH, without a
        // session tag: it cannot be reported here, so mark the remembered section for a later drain
        if NT_SUCCESS!(ntstatus) && (is_paging_io(data) || irql > APC_LEVEL) {
            crate::section_sync::mark_written(flt_objects.FileObject as usize);
        }
        if irql > APC_LEVEL {
            return FLT_POSTOP_FINISHED_PROCESSING;
        }
        // PASSIVE: report the paging writes marked above (the paths live in the section ring)
        crate::section_sync::drain_written(|session, pid, name| {
            FileMonitor::ProcessFileTelemetryEvent(pid, session, INTENT_WRITE, name);
        });
        if !NT_SUCCESS!(ntstatus) {
            return FLT_POSTOP_FINISHED_PROCESSING;
        }
        // the tag check comes first: resolving the name for every write in the system would be costly
        let pid = HandleToU32!(unsafe { PsGetCurrentProcessId() });
        let Some(session) = (unsafe { session_tag_of(pid) }) else {
            return FLT_POSTOP_FINISHED_PROCESSING;
        };
        let Some((file_name, _device, extension)) = file_path(data, flt_objects) else {
            return FLT_POSTOP_FINISHED_PROCESSING;
        };
        if !telemetry_extension(extension.as_deref()) {
            return FLT_POSTOP_FINISHED_PROCESSING;
        }
        if let Ok(name) = try_to_string(&file_name) {
            FileMonitor::ProcessFileTelemetryEvent(pid, session, INTENT_WRITE, name);
        }
        FLT_POSTOP_FINISHED_PROCESSING
    }

    // deletion is a FileDispositionInformation set on the file, not a create: observe it here
    pub(crate) extern "system" fn RamonPreSetInformation(
        data: &mut FLT_CALLBACK_DATA,
        flt_objects: &mut FLT_RELATED_OBJECTS,
        _completion_context: *mut PVOID,
    ) -> FLT_PREOP_CALLBACK_STATUS {
        if data.Iopb.is_null() {
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }
        let info = unsafe { &(*data.Iopb).Parameters.SetFileInformation };
        let kind = match &info.FileInformationClass {
            FILE_INFORMATION_CLASS::FileDispositionInformation
            | FILE_INFORMATION_CLASS::FileDispositionInformationEx => KIND_DELETE,
            FILE_INFORMATION_CLASS::FileRenameInformation
            | FILE_INFORMATION_CLASS::FileRenameInformationEx => KIND_RENAME,
            _ => return FLT_PREOP_SUCCESS_NO_CALLBACK,
        };
        // a delete drops the MOTA marker for this FileId, whatever the process (a FileId NTFS later
        // reuses must not inherit a stale marker)
        if kind == KIND_DELETE {
            unsafe { crate::mota::forget_file(flt_objects) };
        }
        let pid = HandleToU32!(unsafe { PsGetCurrentProcessId() });
        let session = unsafe { session_tag_of(pid) };
        // an untagged process is only interesting when the any-process tier is set
        if session.is_none() && !unsafe { guardrail::any_active() } {
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }
        let Some((file_name, _device, _)) = file_path(data, flt_objects) else {
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        };
        let protected = match session {
            Some(_) => unsafe { guardrail::is_protected_tagged(&file_name) },
            None => unsafe { guardrail::is_protected_any(&file_name) },
        };
        if protected {
            // the any-process tier never refuses SYSTEM or an administrator
            if session.is_none() && unsafe { guardrail::is_privileged() } {
                return FLT_PREOP_SUCCESS_NO_CALLBACK;
            }
            let guardrail_kind = if kind == KIND_DELETE { GRB_DELETE } else { GRB_RENAME };
            block_guardrail(data, pid, session, guardrail_kind, &file_name);
            return FLT_PREOP_COMPLETE;
        }
        // the telemetry record is for the agent tree only
        if let Some(session) = session {
            if let Ok(name) = try_to_string(&file_name) {
                FileMonitor::ProcessFileSetInformationEvent(pid, session, kind, name);
            }
        }
        FLT_PREOP_SUCCESS_NO_CALLBACK
    }

    // a memory-mapped write never reaches RamonPostWrite as the agent (paging I/O, system thread); watch
    // the section instead. A tagged process creating a writable section over a telemetry file is
    // remembered; the release callback then reports a write so the file's content is scanned.
    pub(crate) extern "system" fn RamonPreAcquireForSectionSync(
        data: &mut FLT_CALLBACK_DATA,
        flt_objects: &mut FLT_RELATED_OBJECTS,
        _completion_context: *mut PVOID,
    ) -> FLT_PREOP_CALLBACK_STATUS {
        if let KPROCESSOR_MODE::KernelMode = data.RequestorMode {
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }
        if data.Iopb.is_null() {
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }
        let params = unsafe {
            &*(&(*data.Iopb).Parameters as *const _ as *const AcquireForSectionSynchronization)
        };
        if params.sync_type != SYNC_TYPE_CREATE_SECTION
            || params.page_protection & PAGE_WRITABLE == 0
        {
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }
        let pid = HandleToU32!(unsafe { PsGetCurrentProcessId() });
        let Some(session) = (unsafe { session_tag_of(pid) }) else {
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        };
        let Some((file_name, _device, extension)) = file_path_unsafe(flt_objects) else {
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        };
        if !telemetry_extension(extension.as_deref()) {
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }
        if let Ok(name) = try_to_string(&file_name) {
            crate::section_sync::remember(flt_objects.FileObject as usize, session, pid, name);
        }
        FLT_PREOP_SUCCESS_NO_CALLBACK
    }

    pub(crate) extern "system" fn RamonPreReleaseForSectionSync(
        _data: &mut FLT_CALLBACK_DATA,
        flt_objects: &mut FLT_RELATED_OBJECTS,
        _completion_context: *mut PVOID,
    ) -> FLT_PREOP_CALLBACK_STATUS {
        // the dirty pages are written back before the section is released: report a write so the scan
        // sees the final content. The ring move/free is PASSIVE_LEVEL only.
        if u64::from(unsafe { KeGetCurrentIrql() }) <= APC_LEVEL {
            // intermediate paging writes marked since the last drain
            crate::section_sync::drain_written(|session, pid, name| {
                FileMonitor::ProcessFileTelemetryEvent(pid, session, INTENT_WRITE, name);
            });
            if let Some((session, pid, name)) =
                crate::section_sync::take(flt_objects.FileObject as usize)
            {
                FileMonitor::ProcessFileTelemetryEvent(pid, session, INTENT_WRITE, name);
            }
        }
        FLT_PREOP_SUCCESS_NO_CALLBACK
    }
}

fn telemetry_intent(data: &mut FLT_CALLBACK_DATA) -> Option<u8> {
    let access = desired_access(data);
    // FILE_GENERIC_WRITE shares STANDARD_RIGHTS/SYNCHRONIZE bits with FILE_GENERIC_READ, so it would
    // match every read: test the data bits instead
    if access & (FILE_WRITE_DATA | FILE_APPEND_DATA | GENERIC_WRITE) != 0 {
        Some(INTENT_WRITE)
    } else if access & (FILE_READ_DATA | GENERIC_READ) != 0 {
        Some(INTENT_READ)
    } else {
        None
    }
}

// FILE_DELETE_ON_CLOSE is a create option, not a SetInformation class: cmd's `del` deletes this way
const FILE_DELETE_ON_CLOSE: u32 = 0x0000_1000;

fn delete_on_close(data: &mut FLT_CALLBACK_DATA) -> bool {
    if data.Iopb.is_null() {
        return false;
    }
    let create = unsafe { &(*data.Iopb).Parameters.Create };
    create.Options & FILE_DELETE_ON_CLOSE != 0
}

fn desired_access(data: &mut FLT_CALLBACK_DATA) -> u32 {
    if data.Iopb.is_null() {
        return 0;
    }
    let create = unsafe { &(*data.Iopb).Parameters.Create };
    let Some(security) = (unsafe { (create.SecurityContext as *const IoSecurityContext).as_ref() })
    else {
        return 0;
    };
    security.desired_access
}

// IRP_PAGING_IO (wdm.h): a memory-manager writeback, not a caller's write
const IRP_PAGING_IO: u32 = 0x0000_0002;

fn is_paging_io(data: &mut FLT_CALLBACK_DATA) -> bool {
    !data.Iopb.is_null() && unsafe { (*data.Iopb).IrpFlags } & IRP_PAGING_IO != 0
}

fn telemetry_extension(extension: Option<&str>) -> bool {
    extension.is_some_and(|extension| {
        TELEMETRY_EXTENSIONS.iter().any(|wanted| extension.eq_ignore_ascii_case(wanted))
    })
}

fn canary_extension(extension: Option<&str>) -> bool {
    extension.is_some_and(|extension| extension.eq_ignore_ascii_case(CANARY_EXTENSION))
}

// deny the operation and report it: the caller sees ACCESS_DENIED, the write never reaches the FS
fn block_guardrail(
    data: &mut FLT_CALLBACK_DATA,
    pid: u32,
    session: Option<SessionTag>,
    kind: u8,
    file_name: &str,
) {
    if let Ok(name) = try_to_string(file_name) {
        FileMonitor::ProcessGuardrailBlockedEvent(pid, session, kind, name);
    }
    unsafe { *data.IoStatus.__bindgen_anon_1.Status_mut() = STATUS_ACCESS_DENIED };
}

fn file_path(
    data: &mut FLT_CALLBACK_DATA,
    flt_objects: &mut FLT_RELATED_OBJECTS,
) -> Option<(String, String, Option<String>)> {
    //get file info
    let fni_flags = FLT_FILE_NAME_OPTIONS(FLT_FILE_NAME_OPTIONS::FLT_FILE_NAME_NORMALIZED);
    let mut pfile_name_info = null_mut();

    let ntstatus = unsafe { FltGetFileNameInformation(data, fni_flags, &mut pfile_name_info) };
    if !NT_SUCCESS!(ntstatus) {
        log::warn!("FltGetFileNameInformation failed. Err: 0x{:08x}", ntstatus);
        return None;
    }

    if pfile_name_info.is_null() {
        log::warn!("pfile_name_info is null");
        return None;
    }

    let result = parse_name_info(pfile_name_info, flt_objects);
    unsafe { FltReleaseFileNameInformation(pfile_name_info) };
    result
}

// the section callbacks are FS_FILTER operations, without a create callback data to query a name from
fn file_path_unsafe(
    flt_objects: &mut FLT_RELATED_OBJECTS,
) -> Option<(String, String, Option<String>)> {
    let fni_flags = FLT_FILE_NAME_OPTIONS(FLT_FILE_NAME_OPTIONS::FLT_FILE_NAME_NORMALIZED);
    let mut pfile_name_info = null_mut();
    let ntstatus = unsafe {
        FltGetFileNameInformationUnsafe(
            flt_objects.FileObject as PVOID,
            flt_objects.Instance,
            fni_flags,
            &mut pfile_name_info,
        )
    };
    if !NT_SUCCESS!(ntstatus) || pfile_name_info.is_null() {
        return None;
    }
    let result = parse_name_info(pfile_name_info, flt_objects);
    unsafe { FltReleaseFileNameInformation(pfile_name_info) };
    result
}

// returns (guid path, volume-relative path, extension): the guid path (`\??\Volume{GUID}\...`) is what
// the events carry; `IoReplaceFileObjectName` needs the volume-relative path (`\dir\file`) because the
// file object's name is already relative to its device and the file system does not re-resolve a prefix
fn parse_name_info(
    pfile_name_info: PFLT_FILE_NAME_INFORMATION,
    flt_objects: &mut FLT_RELATED_OBJECTS,
) -> Option<(String, String, Option<String>)> {
    let mut result = None;
    loop {
        let ntstatus = unsafe { FltParseFileNameInformation(pfile_name_info) };
        if !NT_SUCCESS!(ntstatus) {
            log::warn!("FltParseFileNameInformation failed. Err: 0x{:08x}", ntstatus);
            break;
        }

        let mut p_volume = null_mut();
        let ntstatus = unsafe {
            FltGetVolumeFromFileObject(flt_objects.Filter, flt_objects.FileObject, &mut p_volume)
        };
        if !NT_SUCCESS!(ntstatus) {
            log::warn!("FltGetVolumeFromFileObject failed. Err: 0x{:08x}", ntstatus);
            break;
        }

        let mut buffer_size: ULONG = 0;

        let _ = unsafe { FltGetVolumeGuidName(p_volume, null_mut(), &mut buffer_size) };
        let Ok(mut guid_buffer) = try_filled(buffer_size as usize / 2, 0u16) else {
            unsafe { FltObjectDereference(p_volume) };
            break;
        };
        // buffer is owned by guid_buffer; UNICODE_STRING's Drop would RtlFreeUnicodeString it
        let mut guid_name = ManuallyDrop::new(UNICODE_STRING {
            Length: 0,
            MaximumLength: buffer_size as u16,
            ptr: guid_buffer.as_mut_ptr(),
        });

        let ntstatus = unsafe {
            FltGetVolumeGuidName(p_volume, &mut *guid_name as PUNICODE_STRING, &mut buffer_size)
        };
        unsafe { FltObjectDereference(p_volume) };
        if !NT_SUCCESS!(ntstatus) {
            log::debug!("FltGetVolumeGuidName failed. Err: 0x{:08x}", ntstatus);
            break;
        }

        let file_name_info = unsafe { &*pfile_name_info };
        if let (Some(mut guid_name), Some(volume), Some(name)) = (
            guid_name.as_rust_string(),
            file_name_info.Volume.as_rust_string(),
            file_name_info.Name.as_rust_string(),
        ) {
            //log::warn!("{} -{}-{}", guid_name, volume, name);
            if let Some(stripped) = name.strip_prefix(&volume) {
                if try_push_str(&mut guid_name, stripped).is_err() {
                    break;
                }
                let Ok(relative) = try_to_string(stripped) else {
                    break;
                };
                let extension = file_name_info.Extension.as_rust_string();
                result = Some((guid_name, relative, extension));
            }
        }
        //log::warn!("guid_name {:?}", guid_name.as_rust_string());
        break;
    }
    result
}

impl FileMonitor {
    fn ProcessFileEvent(file_name: String) {
        log::trace!("file_name: {}", &file_name);

        let event = FileCreateEvent::new(file_name);
        send_message(event.serialize().unwrap_or_default());
    }

    fn ProcessFileTelemetryEvent(pid: u32, session: SessionTag, intent: u8, file_name: String) {
        log::trace!("file telemetry: {}", &file_name);

        let event = FileTelemetryEvent::new(pid, session, intent, file_name);
        send_message(event.serialize().unwrap_or_default());
    }

    fn ProcessCanaryEvent(pid: u32, session: SessionTag, file_name: String) {
        log::trace!("canary: {}", &file_name);

        let event = CanaryEvent::new(pid, session, file_name);
        send_message(event.serialize().unwrap_or_default());
    }

    fn ProcessFileSetInformationEvent(pid: u32, session: SessionTag, kind: u8, file_name: String) {
        log::trace!("file set information: {}", &file_name);

        let event = FileSetInformationEvent::new(pid, session, kind, file_name);
        send_message(event.serialize().unwrap_or_default());
    }

    fn ProcessGuardrailBlockedEvent(
        pid: u32,
        session: Option<SessionTag>,
        kind: u8,
        file_name: String,
    ) {
        log::trace!("guardrail blocked: {}", &file_name);

        let event = GuardrailBlockedEvent::new(pid, session, kind, file_name);
        send_message(event.serialize().unwrap_or_default());
    }
}
