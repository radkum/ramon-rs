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

pub const INTENT_WRITE: u8 = 0;
pub const INTENT_READ: u8 = 1;

/// A tagged process opened a content file with read or write intent.
#[derive(Debug)]
pub struct FileTelemetryEvent {
    pid: u32,
    session: SessionTag,
    intent: u8,
    path: String,
}

#[cfg(feature = "client")]
#[derive(Debug, Serialize, Deserialize)]
pub struct YamlFileTelemetryEvent {
    pid: Option<u32>,
    path: Option<String>,
}

#[cfg(feature = "client")]
impl From<YamlFileTelemetryEvent> for FileTelemetryEvent {
    fn from(yaml: YamlFileTelemetryEvent) -> Self {
        Self {
            pid: yaml.pid.unwrap_or_default(),
            session: SessionTag {
                root: ariadne::ProcessKey {
                    pid: 0,
                    create_time: 0,
                },
                kind: ariadne::AgentKind::Claude,
                parent_session: None,
            },
            intent: INTENT_WRITE,
            path: yaml.path.unwrap_or_default(),
        }
    }
}

impl FileTelemetryEvent {
    pub fn new(pid: u32, session: SessionTag, intent: u8, path: String) -> Self {
        Self {
            pid,
            session,
            intent,
            path,
        }
    }

    pub fn pid(&self) -> u32 {
        self.pid
    }

    pub fn is_read(&self) -> bool {
        self.intent == INTENT_READ
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn session(&self) -> SessionTag {
        self.session
    }
}

impl Event for FileTelemetryEvent {
    //"FTE " as u32 -> 46 54 45 20
    const EVENT_CLASS: u32 = 0x20455446;
}

impl Serializer for FileTelemetryEvent {
    fn blob_size(&self) -> u32 {
        mem::size_of::<u32>() as u32 + SESSION_BLOB_SIZE + 1 + self.path.blob_size()
    }

    fn to_blob(&self) -> Result<Vec<u8>, TryReserveError> {
        let mut v = Vec::new();
        v.try_reserve_exact(self.blob_size() as usize)?;
        try_extend(&mut v, &self.pid.to_blob()?)?;
        session_to_blob(&mut v, Some(self.session))?;
        try_extend(&mut v, &[self.intent])?;
        try_extend(&mut v, &self.path.to_blob()?)?;
        Ok(v)
    }
}

#[cfg(feature = "client")]
impl Deserializer for FileTelemetryEvent {
    fn from_blob(bytes: &[u8]) -> Option<Self> {
        let pid = u32::from_blob(bytes)?;
        let bytes = bytes.get(4..)?;
        let session = session_from_blob(bytes)??;
        let bytes = bytes.get(SESSION_BLOB_SIZE as usize..)?;
        let intent = *bytes.first()?;
        let bytes = bytes.get(1..)?;
        let path = String::from_blob(bytes)?;
        Some(Self {
            pid,
            session,
            intent,
            path,
        })
    }
}

#[cfg(feature = "client")]
impl MemberHasher for FileTelemetryEvent {
    const EVENT_NAME: &'static str = "FileTelemetry";

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

impl CleaningInfoTrait for FileTelemetryEvent {
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
    fn simple() {
        let session = SessionTag {
            root: ProcessKey {
                pid: 10,
                create_time: 20,
            },
            kind: AgentKind::Claude,
            parent_session: Some(ProcessKey {
                pid: 8,
                create_time: 9,
            }),
        };
        let e1 = FileTelemetryEvent::new(
            12,
            session,
            INTENT_READ,
            r"\??\C:\shem\case.txt".to_string(),
        );
        let event_buff = e1.serialize().unwrap();

        let event_type = get_event_type(event_buff.as_slice());
        assert_eq!(event_type, Some(FileTelemetryEvent::EVENT_CLASS));

        let e2 = FileTelemetryEvent::deserialize(event_buff.as_slice()).unwrap();
        assert_eq!(e2.pid, 12);
        assert_eq!(e2.session, session);
        assert_eq!(e2.path, e1.path);
        assert!(e2.is_read());
    }
}
