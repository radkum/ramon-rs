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

/// A tagged process asked to read a sensitive file and the sensor redirected it to a decoy: `path`
/// is the real file, `decoy` the file the create was actually served from. The agent never sees the
/// secret; the human (untagged) still reads `path`.
#[derive(Debug)]
pub struct MirageRedirectEvent {
    pid: u32,
    session: SessionTag,
    path: String,
    decoy: String,
}

#[cfg(feature = "client")]
#[derive(Debug, Serialize, Deserialize)]
pub struct YamlMirageRedirectEvent {
    pid: Option<u32>,
    path: Option<String>,
    decoy: Option<String>,
}

#[cfg(feature = "client")]
impl From<YamlMirageRedirectEvent> for MirageRedirectEvent {
    fn from(yaml: YamlMirageRedirectEvent) -> Self {
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
            path: yaml.path.unwrap_or_default(),
            decoy: yaml.decoy.unwrap_or_default(),
        }
    }
}

impl MirageRedirectEvent {
    pub fn new(pid: u32, session: SessionTag, path: String, decoy: String) -> Self {
        Self {
            pid,
            session,
            path,
            decoy,
        }
    }

    pub fn pid(&self) -> u32 {
        self.pid
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn decoy(&self) -> &str {
        &self.decoy
    }

    pub fn session(&self) -> SessionTag {
        self.session
    }
}

impl Event for MirageRedirectEvent {
    //"MIRG" as u32 -> 4D 49 52 47
    const EVENT_CLASS: u32 = 0x4752_494D;
}

impl Serializer for MirageRedirectEvent {
    fn blob_size(&self) -> u32 {
        mem::size_of::<u32>() as u32
            + SESSION_BLOB_SIZE
            + self.path.blob_size()
            + self.decoy.blob_size()
    }

    fn to_blob(&self) -> Result<Vec<u8>, TryReserveError> {
        let mut v = Vec::new();
        v.try_reserve_exact(self.blob_size() as usize)?;
        try_extend(&mut v, &self.pid.to_blob()?)?;
        session_to_blob(&mut v, Some(self.session))?;
        try_extend(&mut v, &self.path.to_blob()?)?;
        try_extend(&mut v, &self.decoy.to_blob()?)?;
        Ok(v)
    }
}

#[cfg(feature = "client")]
impl Deserializer for MirageRedirectEvent {
    fn from_blob(bytes: &[u8]) -> Option<Self> {
        let pid = u32::from_blob(bytes)?;
        let bytes = bytes.get(4..)?;
        let session = session_from_blob(bytes)??;
        let bytes = bytes.get(SESSION_BLOB_SIZE as usize..)?;
        let path = String::from_blob(bytes)?;
        let decoy = String::from_blob(bytes.get(path.blob_size() as usize..)?)?;
        Some(Self {
            pid,
            session,
            path,
            decoy,
        })
    }
}

#[cfg(feature = "client")]
impl MemberHasher for MirageRedirectEvent {
    const EVENT_NAME: &'static str = "MirageRedirect";

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
        if !self.decoy.is_empty() {
            v.push(sha256_from_bytes(
                format!("{}+decoy+{}", Self::EVENT_NAME, self.decoy).as_bytes(),
            ));
        }
        v
    }
}

impl CleaningInfoTrait for MirageRedirectEvent {
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
        let e1 = MirageRedirectEvent::new(
            12,
            session,
            r"\??\C:\Users\x\.aws\credentials".to_string(),
            r"\??\C:\Users\x\.aws\credentials.mirage".to_string(),
        );
        let event_buff = e1.serialize().unwrap();

        let event_type = get_event_type(event_buff.as_slice());
        assert_eq!(event_type, Some(MirageRedirectEvent::EVENT_CLASS));

        let e2 = MirageRedirectEvent::deserialize(event_buff.as_slice()).unwrap();
        assert_eq!(e2.pid, 12);
        assert_eq!(e2.session, session);
        assert_eq!(e2.path, e1.path);
        assert_eq!(e2.decoy, e1.decoy);
    }
}
