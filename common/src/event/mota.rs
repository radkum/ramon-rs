#[cfg(feature = "client")]
use alloc::format;
use alloc::{collections::TryReserveError, string::String, vec::Vec};
use core::mem;

use ariadne::SessionTag;
#[cfg(feature = "client")]
use serde::{Deserialize, Serialize};

#[cfg(feature = "client")]
use super::process_create::session_from_blob;
#[cfg(feature = "client")]
use super::Deserializer;
use super::{
    process_create::{session_to_blob, SESSION_BLOB_SIZE},
    Event, Serializer,
};
use crate::{cleaning_info::CleaningInfoTrait, event::Pid, utils::try_extend};
#[cfg(feature = "client")]
use crate::{
    hasher::MemberHasher,
    utils::{sha256_from_bytes, Sha256Buff},
};

/// The file was created or written by an agent process: it now carries Mark-of-the-Agent.
pub const MOTA_MARK: u8 = 0;
/// A non-agent process opened a file that carries Mark-of-the-Agent (delayed execution).
pub const MOTA_HIT: u8 = 1;

/// Volume serial number + 128-bit file id (`FILE_ID_INFORMATION`): identifies a file across rename,
/// move and handle close, where a path would not.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct FileId {
    pub volume: u64,
    pub id: [u8; 16],
}

/// Mark-of-the-Agent. `MOTA_MARK`: a tagged process authored `path` (the marker is `session`).
/// `MOTA_HIT`: an untagged process (`pid`) opened an agent-authored file (the author is `session`).
#[derive(Debug)]
pub struct MotaEvent {
    pid: u32,
    kind: u8,
    session: SessionTag,
    file_id: FileId,
    path: String,
    // image name of the process: the opener for a HIT (its dedup key), empty for a MARK
    image: String,
}

#[cfg(feature = "client")]
#[derive(Debug, Serialize, Deserialize)]
pub struct YamlMotaEvent {
    pid: Option<u32>,
    path: Option<String>,
}

#[cfg(feature = "client")]
impl From<YamlMotaEvent> for MotaEvent {
    fn from(yaml: YamlMotaEvent) -> Self {
        Self {
            pid: yaml.pid.unwrap_or_default(),
            kind: MOTA_MARK,
            session: SessionTag {
                root: ariadne::ProcessKey {
                    pid: 0,
                    create_time: 0,
                },
                kind: ariadne::AgentKind::Claude,
                parent_session: None,
            },
            file_id: FileId {
                volume: 0,
                id: [0; 16],
            },
            path: yaml.path.unwrap_or_default(),
            image: String::new(),
        }
    }
}

impl MotaEvent {
    pub fn new(
        pid: u32,
        kind: u8,
        session: SessionTag,
        file_id: FileId,
        path: String,
        image: String,
    ) -> Self {
        Self {
            pid,
            kind,
            session,
            file_id,
            path,
            image,
        }
    }

    pub fn pid(&self) -> u32 {
        self.pid
    }

    pub fn kind(&self) -> u8 {
        self.kind
    }

    pub fn session(&self) -> SessionTag {
        self.session
    }

    pub fn file_id(&self) -> FileId {
        self.file_id
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    /// Image name of the process: the opener for a HIT, empty for a MARK.
    pub fn image(&self) -> &str {
        &self.image
    }

    pub fn is_hit(&self) -> bool {
        self.kind == MOTA_HIT
    }
}

impl Event for MotaEvent {
    //"MOTA" as u32 -> 4D 4F 54 41
    const EVENT_CLASS: u32 = 0x4154_4F4D;
}

impl Serializer for MotaEvent {
    fn blob_size(&self) -> u32 {
        mem::size_of::<u32>() as u32
            + 1
            + SESSION_BLOB_SIZE
            + mem::size_of::<u64>() as u32
            + 16
            + self.path.blob_size()
            + self.image.blob_size()
    }

    fn to_blob(&self) -> Result<Vec<u8>, TryReserveError> {
        let mut v = Vec::new();
        v.try_reserve_exact(self.blob_size() as usize)?;
        try_extend(&mut v, &self.pid.to_blob()?)?;
        try_extend(&mut v, &[self.kind])?;
        session_to_blob(&mut v, Some(self.session))?;
        try_extend(&mut v, &self.file_id.volume.to_blob()?)?;
        try_extend(&mut v, &self.file_id.id)?;
        try_extend(&mut v, &self.path.to_blob()?)?;
        try_extend(&mut v, &self.image.to_blob()?)?;
        Ok(v)
    }
}

#[cfg(feature = "client")]
impl Deserializer for MotaEvent {
    fn from_blob(bytes: &[u8]) -> Option<Self> {
        let pid = u32::from_blob(bytes)?;
        let bytes = bytes.get(4..)?;
        let kind = *bytes.first()?;
        let bytes = bytes.get(1..)?;
        let session = session_from_blob(bytes)??;
        let bytes = bytes.get(SESSION_BLOB_SIZE as usize..)?;
        let volume = u64::from_blob(bytes)?;
        let bytes = bytes.get(8..)?;
        let mut id = [0u8; 16];
        id.copy_from_slice(bytes.get(..16)?);
        let bytes = bytes.get(16..)?;
        let path = String::from_blob(bytes)?;
        let bytes = bytes.get(path.blob_size() as usize..)?;
        let image = String::from_blob(bytes)?;
        Some(Self {
            pid,
            kind,
            session,
            file_id: FileId { volume, id },
            path,
            image,
        })
    }
}

#[cfg(feature = "client")]
impl MemberHasher for MotaEvent {
    const EVENT_NAME: &'static str = "Mota";

    fn hash_members(&self) -> Vec<Sha256Buff> {
        let mut v = Vec::new();
        if self.pid != 0 {
            v.push(sha256_from_bytes(
                format!("{}+pid+{}", Self::EVENT_NAME, self.pid).as_bytes(),
            ));
        }
        if !self.path.is_empty() {
            v.push(sha256_from_bytes(
                format!("{}+path+{}", Self::EVENT_NAME, self.path).as_bytes(),
            ));
        }
        v
    }
}

impl CleaningInfoTrait for MotaEvent {
    fn get_pid(&self) -> Pid {
        Pid(self.pid)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use alloc::string::ToString;

    use ariadne::{AgentKind, ProcessKey};

    use super::*;
    use crate::event::get_event_type;

    #[test]
    fn round_trip() {
        let session = SessionTag {
            root: ProcessKey {
                pid: 10,
                create_time: 20,
            },
            kind: AgentKind::Cursor,
            parent_session: Some(ProcessKey {
                pid: 8,
                create_time: 9,
            }),
        };
        let file_id = FileId {
            volume: 0x1122_3344_5566_7788,
            id: [7; 16],
        };
        for kind in [MOTA_MARK, MOTA_HIT] {
            let e1 = MotaEvent::new(
                12,
                kind,
                session,
                file_id,
                r"\??\C:\shem\.git\hooks\pre-commit".to_string(),
                "git.exe".to_string(),
            );
            let event_buff = e1.serialize().unwrap();

            let event_type = get_event_type(event_buff.as_slice());
            assert_eq!(event_type, Some(MotaEvent::EVENT_CLASS));

            let e2 = MotaEvent::deserialize(event_buff.as_slice()).unwrap();
            assert_eq!(e2.pid, 12);
            assert_eq!(e2.kind, kind);
            assert_eq!(e2.session, session);
            assert_eq!(e2.file_id, file_id);
            assert_eq!(e2.path, e1.path);
            assert_eq!(e2.image, "git.exe");
            assert_eq!(e2.is_hit(), kind == MOTA_HIT);
        }
    }
}
