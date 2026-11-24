//! Notify callbacks: process create, image load, registry set-value and process handle opens.
//! All four run at PASSIVE_LEVEL; none of them blocks on user mode directly.
pub(super) mod image_load_notify;
pub(super) mod object_notify;
pub(super) mod process_notify;
pub(super) mod registry_notify;

pub(super) use image_load_notify::OnImageLoadNotify;
pub(super) use object_notify::{start as start_object_notify, stop as stop_object_notify};
pub(super) use process_notify::{
    adopt, adopt_tag, clear_tree, init_tree, session_tag_of, OnProcessNotify,
};
pub(super) use registry_notify::{MmCopyMemory, OnRegistryNotify, MM_COPY_MEMORY_VIRTUAL};
