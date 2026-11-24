use alloc::{collections::TryReserveError, string::String, vec::Vec};
use core::mem;

use ariadne::SessionTag;

#[cfg(feature = "client")]
use super::{process_create::session_from_blob, Deserializer};
use super::{
    process_create::{session_to_blob, SESSION_BLOB_SIZE},
    Event, Serializer,
};
use crate::{cleaning_info::CleaningInfoTrait, event::Pid, utils::try_extend};

/// A process in `session` opened a handle to another process: `ObRegisterCallbacks` pre-operation,
/// handle create only. `image` is the kernel's short name of the target (at most 15 characters) and
/// `access` the requested access mask.
#[derive(Debug)]
pub struct HandleOpenEvent {
    caller_pid: u32,
    session: SessionTag,
    target_pid: u32,
    target_create_time: u64,
    access: u32,
    image: String,
}

impl HandleOpenEvent {
    pub fn new(
        caller_pid: u32,
        session: SessionTag,
        target_pid: u32,
        target_create_time: u64,
        access: u32,
        image: String,
    ) -> Self {
        Self {
            caller_pid,
            session,
            target_pid,
            target_create_time,
            access,
            image,
        }
    }

    #[cfg(feature = "client")]
    pub fn caller_pid(&self) -> u32 {
        self.caller_pid
    }

    #[cfg(feature = "client")]
    pub fn session(&self) -> SessionTag {
        self.session
    }

    #[cfg(feature = "client")]
    pub fn target_pid(&self) -> u32 {
        self.target_pid
    }

    #[cfg(feature = "client")]
    pub fn target_create_time(&self) -> u64 {
        self.target_create_time
    }

    #[cfg(feature = "client")]
    pub fn access(&self) -> u32 {
        self.access
    }

    #[cfg(feature = "client")]
    pub fn image(&self) -> &str {
        &self.image
    }
}

impl Event for HandleOpenEvent {
    //"HKO " as u32-> 48 4B 4F 20
    const EVENT_CLASS: u32 = 0x204F4B48;
}

impl Serializer for HandleOpenEvent {
    fn blob_size(&self) -> u32 {
        mem::size_of::<u32>() as u32 * 2
            + mem::size_of::<u64>() as u32
            + mem::size_of::<u32>() as u32
            + SESSION_BLOB_SIZE
            + self.image.blob_size()
    }

    fn to_blob(&self) -> Result<Vec<u8>, TryReserveError> {
        let mut v = Vec::new();
        v.try_reserve_exact(self.blob_size() as usize)?;
        try_extend(&mut v, &self.caller_pid.to_blob()?)?;
        try_extend(&mut v, &self.target_pid.to_blob()?)?;
        try_extend(&mut v, &self.target_create_time.to_blob()?)?;
        try_extend(&mut v, &self.access.to_blob()?)?;
        session_to_blob(&mut v, Some(self.session))?;
        try_extend(&mut v, &self.image.to_blob()?)?;
        Ok(v)
    }
}

#[cfg(feature = "client")]
impl Deserializer for HandleOpenEvent {
    fn from_blob(bytes: &[u8]) -> Option<Self> {
        let caller_pid = u32::from_blob(bytes)?;
        let target_pid = u32::from_blob(bytes.get(4..)?)?;
        let target_create_time = u64::from_blob(bytes.get(8..)?)?;
        let access = u32::from_blob(bytes.get(16..)?)?;
        let rest = bytes.get(20..)?;
        let session = session_from_blob(rest.get(..SESSION_BLOB_SIZE as usize)?)??;
        let image = String::from_blob(rest.get(SESSION_BLOB_SIZE as usize..)?)?;
        Some(Self {
            caller_pid,
            session,
            target_pid,
            target_create_time,
            access,
            image,
        })
    }
}

impl CleaningInfoTrait for HandleOpenEvent {
    fn get_pid(&self) -> Pid {
        Pid(self.caller_pid)
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
            kind: AgentKind::Claude,
            parent_session: None,
        };
        let e1 = HandleOpenEvent::new(
            500,
            session,
            4,
            0x01db_0000_1234_5678,
            0x1f_0fff,
            String::from("lsass.exe"),
        );
        let buff = e1.serialize().unwrap();
        assert_eq!(get_event_type(&buff), Some(HandleOpenEvent::EVENT_CLASS));
        let e2 = HandleOpenEvent::deserialize(&buff).unwrap();
        assert_eq!((e2.caller_pid, e2.target_pid), (500, 4));
        assert_eq!(
            (e2.target_create_time, e2.access),
            (0x01db_0000_1234_5678, 0x1f_0fff)
        );
        assert_eq!((e2.session, e2.image.as_str()), (session, "lsass.exe"));
        assert!(HandleOpenEvent::deserialize(&buff[..buff.len() - 1]).is_none());
    }
}
