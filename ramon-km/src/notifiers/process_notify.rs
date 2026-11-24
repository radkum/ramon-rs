//! Process-create notify callback. Runs at PASSIVE_LEVEL before the new process starts, so the
//! event carries the parent pid, the image name and the command line.
use alloc::string::String;

use ariadne::{ProcessKey, ProcessTree, SessionTag};
use common::event::{
    process_create::{command_line_from_utf16, ProcessCreateEvent},
    session_assigned::SessionAssignedEvent,
    Event,
};
use kernel_macros::HandleToU32;
use kernel_string::UNICODE_STRING;
use km_api_sys::ntddk::{PPS_CREATE_NOTIFY_INFO, PS_CREATE_NOTIFY_INFO};
use winapi::{
    km::wdm::PEPROCESS,
    shared::{ntdef::HANDLE, ntstatus::STATUS_INSUFFICIENT_RESOURCES},
};

use crate::{np_alloc::NonPaged, send_message::send_message, spinlock::SpinLocked};

// not declared in km-api-sys
extern "system" {
    fn PsGetProcessCreateTimeQuadPart(process: PEPROCESS) -> i64;
}

// The WFP callout reads the tag at DISPATCH_LEVEL, so the tree lives in NonPaged pool and is
// protected by a spinlock instead of a FAST_MUTEX (which is illegal above APC_LEVEL).
static G_TREE: SpinLocked<ProcessTree<NonPaged>> = SpinLocked::new(ProcessTree::new_in(NonPaged));

/// Initializes the tree lock; call once from DriverEntry before any callback can run.
pub(crate) unsafe fn init_tree() {
    G_TREE.init();
}

/// Frees the tree; call only after the process notify routine is removed.
pub(crate) unsafe fn clear_tree() {
    *G_TREE.lock() = ProcessTree::new_in(NonPaged);
}

pub(crate) unsafe fn session_tag_of(pid: u32) -> Option<SessionTag> {
    G_TREE.lock().tag_of(pid)
}

// processes tagged by one adoption whose SessionAssigned is sent; the rest are only logged
const MAX_ASSIGNED: usize = 64;

pub(crate) unsafe fn adopt(child: ProcessKey, causal: ProcessKey) -> bool {
    adopt_then_send(|assigned| G_TREE.lock().adopt(child, causal, assigned))
}

pub(crate) unsafe fn adopt_tag(child: ProcessKey, tag: SessionTag) -> bool {
    adopt_then_send(|assigned| G_TREE.lock().adopt_tag(child, tag, assigned))
}

// send_message can block on a full queue, so it runs after the tree lock is released
unsafe fn adopt_then_send(
    adopt: impl FnOnce(&mut dyn FnMut(ProcessKey, SessionTag)) -> Option<SessionTag>,
) -> bool {
    let mut keys = [ProcessKey { pid: 0, create_time: 0 }; MAX_ASSIGNED];
    let mut len = 0;
    let tag = {
        adopt(&mut |key, _| {
            if len < MAX_ASSIGNED {
                keys[len] = key;
            }
            len += 1;
        })
    };
    if len > MAX_ASSIGNED {
        log::warn!("SessionAssigned not sent for {} processes", len - MAX_ASSIGNED);
    }
    if let Some(tag) = tag {
        for key in &keys[..len.min(MAX_ASSIGNED)] {
            send_assigned(*key, tag);
        }
    }
    tag.is_some()
}

// queued behind the process's ProcessCreateEvent, so the client sees creation first
fn send_assigned(key: ProcessKey, tag: SessionTag) {
    send_message(
        SessionAssignedEvent::new(key.pid, key.create_time, tag).serialize().unwrap_or_default(),
    );
}

unsafe fn command_line(line: *const UNICODE_STRING) -> String {
    match line.as_ref().filter(|line| !line.ptr.is_null()) {
        Some(line) => {
            command_line_from_utf16(core::slice::from_raw_parts(line.ptr, line.Length as usize / 2))
        },
        None => String::new(),
    }
}

pub extern "system" fn OnProcessNotify(
    process: PEPROCESS,
    process_id: HANDLE,
    create_info: PPS_CREATE_NOTIFY_INFO,
) {
    unsafe {
        log::info!("OnProcessNotify");
        let key = ProcessKey {
            pid: HandleToU32!(process_id),
            create_time: PsGetProcessCreateTimeQuadPart(process) as u64,
        };
        if !create_info.is_null() {
            let create_info: &mut PS_CREATE_NOTIFY_INFO = &mut *create_info;

            let image_file_name = &*create_info.ImageFileName;
            let path = image_file_name.as_rust_string().unwrap_or_default();
            let command_line = command_line(create_info.CommandLine);

            let session = G_TREE.lock().on_create(
                key,
                HandleToU32!(create_info.ParentProcessId),
                HandleToU32!(create_info.CreatingThreadId.UniqueProcess),
                &path,
                &command_line,
            );
            let session = match session {
                Ok(session) => session,
                // an untracked agent descendant would escape its session: deny it
                Err(e) if e.tag.is_some() => {
                    create_info.CreationStatus = STATUS_INSUFFICIENT_RESOURCES;
                    return;
                },
                Err(_) => None,
            };

            let event = ProcessCreateEvent::new(
                key.pid,
                HandleToU32!(create_info.ParentProcessId),
                key.create_time,
                path,
                session,
                command_line,
            );
            send_message(event.serialize().unwrap_or_default());
        } else {
            G_TREE.lock().on_exit(key);
        }
    }
}
