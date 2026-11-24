#[cfg(feature = "client")]
use alloc::format;
use alloc::{collections::TryReserveError, string::String, vec::Vec};
use core::mem;

use ariadne::{AgentKind, ProcessKey, SessionTag};
#[cfg(feature = "client")]
use serde::{Deserialize, Serialize};

#[cfg(feature = "client")]
use super::Deserializer;
use super::{Event, Serializer};
use crate::{
    cleaning_info::CleaningInfoTrait,
    event::Pid,
    utils::{try_extend, try_push_str},
};
#[cfg(feature = "client")]
use crate::{
    deserializer::DeserializerWithSize,
    hasher::MemberHasher,
    utils::{sha256_from_bytes, Sha256Buff},
};

#[derive(Debug)]
pub struct ProcessCreateEvent {
    pid: u32,
    parent_id: u32,
    create_time: u64,
    path: String,
    session: Option<SessionTag>,
    command_line: String,
}

/// A longer command line is cut at a char boundary; an ASCII one (at most 32767 chars) always fits.
pub const MAX_COMMAND_LINE: usize = 0x8000;

/// Lossy, so that an unpaired surrogate cannot blank the line; empty when the allocation fails.
pub fn command_line_from_utf16(units: &[u16]) -> String {
    let chars = || {
        char::decode_utf16(units.iter().copied()).map(|c| c.unwrap_or(char::REPLACEMENT_CHARACTER))
    };
    let mut len = 0;
    for c in chars() {
        if len + c.len_utf8() > MAX_COMMAND_LINE {
            break;
        }
        len += c.len_utf8();
    }
    let mut s = String::new();
    if s.try_reserve_exact(len).is_err() {
        return s;
    }
    for c in chars() {
        if s.len() + c.len_utf8() > len {
            break;
        }
        // within the reserved capacity: cannot fail
        let _ = try_push_str(&mut s, c.encode_utf8(&mut [0; 4]));
    }
    s
}

#[cfg(feature = "client")]
#[derive(Debug, Serialize, Deserialize)]
pub struct YamlProcessCreateEvent {
    pid: Option<u32>,
    parent_id: Option<u32>,
    path: Option<String>,
}

#[cfg(feature = "client")]
impl From<YamlProcessCreateEvent> for ProcessCreateEvent {
    fn from(yaml: YamlProcessCreateEvent) -> Self {
        Self {
            pid: yaml.pid.unwrap_or_default(),
            parent_id: yaml.parent_id.unwrap_or_default(),
            create_time: 0,
            path: yaml.path.unwrap_or_default(),
            session: None,
            command_line: String::new(),
        }
    }
}

impl ProcessCreateEvent {
    pub fn new(
        pid: u32,
        parent_id: u32,
        create_time: u64,
        path: String,
        session: Option<SessionTag>,
        command_line: String,
    ) -> Self {
        Self {
            pid,
            parent_id,
            create_time,
            path,
            session,
            command_line,
        }
    }

    #[cfg(feature = "client")]
    pub fn pid(&self) -> u32 {
        self.pid
    }

    #[cfg(feature = "client")]
    pub fn parent_id(&self) -> u32 {
        self.parent_id
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn command_line(&self) -> &str {
        &self.command_line
    }

    /// FILETIME units; with `pid` it identifies the process despite PID reuse.
    pub fn create_time(&self) -> u64 {
        self.create_time
    }

    pub fn session(&self) -> Option<SessionTag> {
        self.session
    }
}

// session on the wire: kind (0 = none), root pid, root create time, parent session pid (0 = none), its create time,
// `Persisted` from pid (0 = none), its create time
pub(crate) const SESSION_BLOB_SIZE: u32 = 4 + 4 + 8 + 4 + 8 + 4 + 8;

pub(crate) fn kind_to_u32(kind: AgentKind) -> u32 {
    match kind {
        AgentKind::Claude => 1,
        AgentKind::Cursor => 2,
        AgentKind::Codex => 3,
        AgentKind::Persisted { .. } => 4,
        AgentKind::Opencode => 5,
        AgentKind::Gemini => 6,
        AgentKind::Grok => 7,
    }
}

pub(crate) fn from_of(kind: AgentKind) -> ProcessKey {
    match kind {
        AgentKind::Persisted { from } => from,
        _ => ProcessKey {
            pid: 0,
            create_time: 0,
        },
    }
}

pub(crate) fn kind_from_u32(kind: u32, from: ProcessKey) -> Option<AgentKind> {
    match kind {
        1 => Some(AgentKind::Claude),
        2 => Some(AgentKind::Cursor),
        3 => Some(AgentKind::Codex),
        4 => Some(AgentKind::Persisted { from }),
        5 => Some(AgentKind::Opencode),
        6 => Some(AgentKind::Gemini),
        7 => Some(AgentKind::Grok),
        _ => None,
    }
}

pub(crate) fn session_to_blob(
    v: &mut Vec<u8>,
    session: Option<SessionTag>,
) -> Result<(), TryReserveError> {
    let kind = session.map_or(0, |s| kind_to_u32(s.kind));
    let root = session.map_or(
        ProcessKey {
            pid: 0,
            create_time: 0,
        },
        |s| s.root,
    );
    let parent = session
        .and_then(|s| s.parent_session)
        .unwrap_or(ProcessKey {
            pid: 0,
            create_time: 0,
        });
    let from = session.map_or(
        ProcessKey {
            pid: 0,
            create_time: 0,
        },
        |s| from_of(s.kind),
    );
    try_extend(v, &kind.to_blob()?)?;
    try_extend(v, &root.pid.to_blob()?)?;
    try_extend(v, &root.create_time.to_blob()?)?;
    try_extend(v, &parent.pid.to_blob()?)?;
    try_extend(v, &parent.create_time.to_blob()?)?;
    try_extend(v, &from.pid.to_blob()?)?;
    try_extend(v, &from.create_time.to_blob()?)
}

#[cfg(feature = "client")]
pub(crate) fn session_from_blob(bytes: &[u8]) -> Option<Option<SessionTag>> {
    let key = |offset: usize| -> Option<ProcessKey> {
        Some(ProcessKey {
            pid: u32::from_blob(bytes.get(offset..)?)?,
            create_time: u64::from_blob(bytes.get(offset + 4..)?)?,
        })
    };
    let kind = u32::from_blob(bytes)?;
    let root = key(4)?;
    let parent = key(16)?;
    let from = key(28)?;
    Some(kind_from_u32(kind, from).map(|kind| SessionTag {
        root,
        kind,
        parent_session: (parent.pid != 0).then_some(parent),
    }))
}

impl Event for ProcessCreateEvent {
    //"PRO " as u32-> 50 52 4F 20
    const EVENT_CLASS: u32 = 0x204F5250;
}

impl Serializer for ProcessCreateEvent {
    fn blob_size(&self) -> u32 {
        mem::size_of::<u32>() as u32
            + mem::size_of::<u32>() as u32
            + mem::size_of::<u64>() as u32
            + SESSION_BLOB_SIZE
            + self.path.blob_size()
            + self.command_line.blob_size()
    }

    fn to_blob(&self) -> Result<Vec<u8>, TryReserveError> {
        let mut v = Vec::new();
        let v_len = self.blob_size() as usize;
        v.try_reserve_exact(v_len)?;

        try_extend(&mut v, &self.pid.to_blob()?)?;
        try_extend(&mut v, &self.parent_id.to_blob()?)?;
        try_extend(&mut v, &self.create_time.to_blob()?)?;
        session_to_blob(&mut v, self.session)?;
        try_extend(&mut v, &self.path.to_blob()?)?;
        try_extend(&mut v, &self.command_line.to_blob()?)?;

        Ok(v)
    }
}

#[cfg(feature = "client")]
impl Deserializer for ProcessCreateEvent {
    fn from_blob(bytes: &[u8]) -> Option<Self> {
        let pid = u32::from_blob(bytes)?;
        let bytes = bytes.get(4..)?;

        let parent_id = u32::from_blob(bytes)?;
        let bytes = bytes.get(4..)?;

        let create_time = u64::from_blob(bytes)?;
        let bytes = bytes.get(8..)?;

        let session = session_from_blob(bytes)?;
        let bytes = bytes.get(SESSION_BLOB_SIZE as usize..)?;

        let (path, size) = String::from_blob_with_size(bytes)?;
        let command_line = String::from_blob(bytes.get(size..)?)?;
        Some(Self {
            pid,
            parent_id,
            create_time,
            path,
            session,
            command_line,
        })
    }
}

#[cfg(feature = "client")]
impl MemberHasher for ProcessCreateEvent {
    const EVENT_NAME: &'static str = "ProcessCreate";

    fn hash_members(&self) -> Vec<Sha256Buff> {
        let mut v = Vec::new();

        if self.pid != 0 {
            let pid = format!("{}+{}+{}", Self::EVENT_NAME, "pid", self.pid);
            v.push(sha256_from_bytes(pid.as_bytes()));
        }

        if self.parent_id != 0 {
            let parent_id = format!("{}+{}+{}", Self::EVENT_NAME, "parent_id", self.parent_id);
            v.push(sha256_from_bytes(parent_id.as_bytes()));
        }

        if !self.path.is_empty() {
            let path = format!("{}+{}+{}", Self::EVENT_NAME, "path", self.path);
            v.push(sha256_from_bytes(path.as_bytes()));
        }

        v
    }
}

impl CleaningInfoTrait for ProcessCreateEvent {
    fn get_pid(&self) -> Pid {
        Pid(self.pid)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use alloc::string::ToString;

    use super::*;
    use crate::event::get_event_type;

    #[test]
    fn simple() {
        let e1 = ProcessCreateEvent::new(
            123,
            234,
            0x01db_0000_1234_5678,
            "elo mordo".to_string(),
            None,
            String::new(),
        );
        let event_buff = e1.serialize().unwrap();

        let event_type = get_event_type(event_buff.as_slice());
        assert_eq!(event_type, Some(ProcessCreateEvent::EVENT_CLASS));

        let e2 = ProcessCreateEvent::deserialize(event_buff.as_slice()).unwrap();
        assert_eq!(e1.pid, e2.pid);
        assert_eq!(e1.parent_id, e2.parent_id);
        assert_eq!(e1.create_time, e2.create_time);
        assert_eq!(e1.path, e2.path);
        assert_eq!(e2.session, None);
        assert_eq!(e2.command_line, "");
    }

    #[test]
    fn command_line_round_trip() {
        for line in [
            "schtasks /create /tn \"demo task\" /tr \"cmd /c exit\" /f",
            "zażółć",
            "abc",
        ] {
            let e1 = ProcessCreateEvent::new(
                1,
                2,
                3,
                r"C:\x\schtasks.exe".to_string(),
                None,
                line.to_string(),
            );
            let e2 = ProcessCreateEvent::deserialize(e1.serialize().unwrap().as_slice()).unwrap();
            assert_eq!(e2.path, e1.path);
            assert_eq!(e2.command_line, line);
        }
    }

    #[test]
    fn command_line_is_lossy_and_cut_at_char_boundary() {
        let utf16 = |s: &str| s.encode_utf16().collect::<Vec<u16>>();
        assert_eq!(command_line_from_utf16(&[0x61, 0xD800, 0x62]), "a\u{FFFD}b");
        let ascii = "a".repeat(32767);
        assert_eq!(command_line_from_utf16(&utf16(&ascii)), ascii);
        // 'ż' takes 2 bytes: the cut drops the one that would cross the limit
        let wide = "ż".repeat(MAX_COMMAND_LINE / 2 + 1);
        let cut = command_line_from_utf16(&utf16(&format!("a{wide}")));
        assert_eq!(cut.len(), MAX_COMMAND_LINE - 1);
        assert!(cut.starts_with("aż"));
    }

    #[test]
    fn session_round_trip() {
        let session = SessionTag {
            root: ProcessKey {
                pid: 200,
                create_time: 0x1234_5678_9abc,
            },
            kind: AgentKind::Cursor,
            parent_session: Some(ProcessKey {
                pid: 100,
                create_time: 7,
            }),
        };
        let persisted = SessionTag {
            kind: AgentKind::Persisted {
                from: ProcessKey {
                    pid: 300,
                    create_time: 9,
                },
            },
            ..session
        };
        let opencode = SessionTag {
            kind: AgentKind::Opencode,
            ..session
        };
        for session in [
            Some(session),
            Some(SessionTag {
                parent_session: None,
                ..session
            }),
            Some(persisted),
            Some(opencode),
        ] {
            let e1 =
                ProcessCreateEvent::new(1, 2, 3, "node.exe".to_string(), session, String::new());
            let e2 = ProcessCreateEvent::deserialize(e1.serialize().unwrap().as_slice()).unwrap();
            assert_eq!(e2.session, session);
            assert_eq!(e2.path, e1.path);
        }
    }
}
