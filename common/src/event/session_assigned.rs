use alloc::{collections::TryReserveError, vec::Vec};
use core::mem;

use ariadne::SessionTag;

#[cfg(feature = "client")]
use super::{process_create::session_from_blob, Deserializer};
use super::{
    process_create::{session_to_blob, SESSION_BLOB_SIZE},
    Event, Serializer,
};
use crate::{cleaning_info::CleaningInfoTrait, event::Pid, utils::try_extend};

/// A process created untagged got `session` later (adoption, or as a descendant of an adopted process).
#[derive(Debug)]
pub struct SessionAssignedEvent {
    pid: u32,
    create_time: u64,
    session: SessionTag,
}

impl SessionAssignedEvent {
    pub fn new(pid: u32, create_time: u64, session: SessionTag) -> Self {
        Self {
            pid,
            create_time,
            session,
        }
    }

    #[cfg(feature = "client")]
    pub fn pid(&self) -> u32 {
        self.pid
    }

    pub fn create_time(&self) -> u64 {
        self.create_time
    }

    pub fn session(&self) -> SessionTag {
        self.session
    }
}

impl Event for SessionAssignedEvent {
    //"SES " as u32-> 53 45 53 20
    const EVENT_CLASS: u32 = 0x20534553;
}

impl Serializer for SessionAssignedEvent {
    fn blob_size(&self) -> u32 {
        mem::size_of::<u32>() as u32 + mem::size_of::<u64>() as u32 + SESSION_BLOB_SIZE
    }

    fn to_blob(&self) -> Result<Vec<u8>, TryReserveError> {
        let mut v = Vec::new();
        v.try_reserve_exact(self.blob_size() as usize)?;
        try_extend(&mut v, &self.pid.to_blob()?)?;
        try_extend(&mut v, &self.create_time.to_blob()?)?;
        session_to_blob(&mut v, Some(self.session))?;
        Ok(v)
    }
}

#[cfg(feature = "client")]
impl Deserializer for SessionAssignedEvent {
    fn from_blob(bytes: &[u8]) -> Option<Self> {
        let pid = u32::from_blob(bytes)?;
        let create_time = u64::from_blob(bytes.get(4..)?)?;
        let session = session_from_blob(bytes.get(12..12 + SESSION_BLOB_SIZE as usize)?)??;
        Some(Self {
            pid,
            create_time,
            session,
        })
    }
}

impl CleaningInfoTrait for SessionAssignedEvent {
    fn get_pid(&self) -> Pid {
        Pid(self.pid)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use ariadne::{AgentKind, ProcessKey};

    use super::*;
    use crate::event::get_event_type;

    #[test]
    fn round_trip() {
        let session = SessionTag {
            root: ProcessKey {
                pid: 200,
                create_time: 0x1234_5678_9abc,
            },
            kind: AgentKind::Persisted {
                from: ProcessKey {
                    pid: 300,
                    create_time: 9,
                },
            },
            parent_session: Some(ProcessKey {
                pid: 100,
                create_time: 7,
            }),
        };
        let e1 = SessionAssignedEvent::new(500, 0x01db_0000_1234_5678, session);
        let buff = e1.serialize().unwrap();
        assert_eq!(
            get_event_type(&buff),
            Some(SessionAssignedEvent::EVENT_CLASS)
        );
        let e2 = SessionAssignedEvent::deserialize(&buff).unwrap();
        assert_eq!(
            (e2.pid, e2.create_time, e2.session),
            (e1.pid, e1.create_time, session)
        );
        assert!(SessionAssignedEvent::deserialize(&buff[..buff.len() - 1]).is_none());
    }
}
