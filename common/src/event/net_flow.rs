#[cfg(feature = "client")]
use alloc::format;
use alloc::{collections::TryReserveError, vec::Vec};
use core::mem;

use ariadne::SessionTag;

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

/// Outbound flow direction (matches `FWP_DIRECTION_OUTBOUND`).
pub const DIRECTION_OUTBOUND: u8 = 0;
/// Inbound flow direction (matches `FWP_DIRECTION_INBOUND`).
pub const DIRECTION_INBOUND: u8 = 1;

/// One network flow of a process in `session`, seen by the WFP callout at `ALE_FLOW_ESTABLISHED`
/// (one event per 5-tuple; for UDP the first datagram to the destination). Addresses are the raw
/// network-order bytes (4 significant for IPv4, 16 for IPv6); `family` is 4 or 6, `protocol` an
/// `IPPROTO_*` value, `direction` `DIRECTION_OUTBOUND`/`DIRECTION_INBOUND`.
#[derive(Debug)]
pub struct NetFlowEvent {
    pid: u32,
    session: SessionTag,
    direction: u8,
    family: u8,
    protocol: u8,
    local_addr: [u8; 16],
    remote_addr: [u8; 16],
    local_port: u16,
    remote_port: u16,
}

impl NetFlowEvent {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        pid: u32,
        session: SessionTag,
        direction: u8,
        family: u8,
        protocol: u8,
        local_addr: [u8; 16],
        remote_addr: [u8; 16],
        local_port: u16,
        remote_port: u16,
    ) -> Self {
        Self {
            pid,
            session,
            direction,
            family,
            protocol,
            local_addr,
            remote_addr,
            local_port,
            remote_port,
        }
    }

    pub fn pid(&self) -> u32 {
        self.pid
    }

    pub fn session(&self) -> SessionTag {
        self.session
    }

    pub fn direction(&self) -> u8 {
        self.direction
    }

    pub fn family(&self) -> u8 {
        self.family
    }

    pub fn protocol(&self) -> u8 {
        self.protocol
    }

    pub fn local_addr(&self) -> [u8; 16] {
        self.local_addr
    }

    pub fn remote_addr(&self) -> [u8; 16] {
        self.remote_addr
    }

    pub fn local_port(&self) -> u16 {
        self.local_port
    }

    pub fn remote_port(&self) -> u16 {
        self.remote_port
    }
}

impl Event for NetFlowEvent {
    //"NFLW" as u32 -> 4E 46 4C 57
    const EVENT_CLASS: u32 = 0x574C_464E;
}

impl Serializer for NetFlowEvent {
    fn blob_size(&self) -> u32 {
        mem::size_of::<u32>() as u32 + SESSION_BLOB_SIZE + 3 + 32 + mem::size_of::<u16>() as u32 * 2
    }

    fn to_blob(&self) -> Result<Vec<u8>, TryReserveError> {
        let mut v = Vec::new();
        v.try_reserve_exact(self.blob_size() as usize)?;
        try_extend(&mut v, &self.pid.to_blob()?)?;
        session_to_blob(&mut v, Some(self.session))?;
        try_extend(&mut v, &[self.direction, self.family, self.protocol])?;
        try_extend(&mut v, &self.local_addr)?;
        try_extend(&mut v, &self.remote_addr)?;
        try_extend(&mut v, &self.local_port.to_le_bytes())?;
        try_extend(&mut v, &self.remote_port.to_le_bytes())?;
        Ok(v)
    }
}

#[cfg(feature = "client")]
impl Deserializer for NetFlowEvent {
    fn from_blob(bytes: &[u8]) -> Option<Self> {
        let pid = u32::from_blob(bytes)?;
        let bytes = bytes.get(4..)?;
        let session = session_from_blob(bytes)??;
        let bytes = bytes.get(SESSION_BLOB_SIZE as usize..)?;
        let direction = *bytes.first()?;
        let family = *bytes.get(1..)?.first()?;
        let protocol = *bytes.get(2..)?.first()?;
        let bytes = bytes.get(3..)?;
        let local_addr: [u8; 16] = bytes.get(..16)?.try_into().ok()?;
        let remote_addr: [u8; 16] = bytes.get(16..32)?.try_into().ok()?;
        let local_port = u16::from_le_bytes(bytes.get(32..34)?.try_into().ok()?);
        let remote_port = u16::from_le_bytes(bytes.get(34..36)?.try_into().ok()?);
        Some(Self {
            pid,
            session,
            direction,
            family,
            protocol,
            local_addr,
            remote_addr,
            local_port,
            remote_port,
        })
    }
}

#[cfg(feature = "client")]
impl MemberHasher for NetFlowEvent {
    const EVENT_NAME: &'static str = "NetFlow";

    fn hash_members(&self) -> Vec<Sha256Buff> {
        let mut v = Vec::new();
        if self.pid != 0 {
            v.push(sha256_from_bytes(
                format!("{}+pid+{}", Self::EVENT_NAME, self.pid).as_bytes(),
            ));
        }
        if self.remote_port != 0 {
            v.push(sha256_from_bytes(
                format!("{}+remote_port+{}", Self::EVENT_NAME, self.remote_port).as_bytes(),
            ));
        }
        v
    }
}

impl CleaningInfoTrait for NetFlowEvent {
    fn get_pid(&self) -> Pid {
        Pid(self.pid)
    }
}

/// Formats an address for the log: dotted quad for IPv4, RFC 5952-ish groups for IPv6.
#[cfg(feature = "client")]
pub fn format_address(family: u8, addr: &[u8; 16]) -> alloc::string::String {
    if family == 4 {
        format!("{}.{}.{}.{}", addr[0], addr[1], addr[2], addr[3])
    } else {
        let mut s = alloc::string::String::new();
        for i in 0..8 {
            if i != 0 {
                s.push(':');
            }
            let group = u16::from_be_bytes([addr[i * 2], addr[i * 2 + 1]]);
            s.push_str(&format!("{group:x}"));
        }
        s
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use alloc::string::ToString;

    use ariadne::{AgentKind, ProcessKey};

    use super::*;
    use crate::event::get_event_type;

    fn session() -> SessionTag {
        SessionTag {
            root: ProcessKey {
                pid: 10,
                create_time: 20,
            },
            kind: AgentKind::Claude,
            parent_session: Some(ProcessKey {
                pid: 8,
                create_time: 9,
            }),
        }
    }

    #[test]
    fn round_trip_v4() {
        let mut local = [0u8; 16];
        local[..4].copy_from_slice(&[10, 0, 0, 5]);
        let mut remote = [0u8; 16];
        remote[..4].copy_from_slice(&[93, 184, 216, 34]);
        let e1 = NetFlowEvent::new(
            12,
            session(),
            DIRECTION_OUTBOUND,
            4,
            6,
            local,
            remote,
            51234,
            443,
        );
        let buff = e1.serialize().unwrap();
        assert_eq!(get_event_type(&buff), Some(NetFlowEvent::EVENT_CLASS));
        let e2 = NetFlowEvent::deserialize(&buff).unwrap();
        assert_eq!(e2.pid, 12);
        assert_eq!(e2.session, session());
        assert_eq!(e2.direction, DIRECTION_OUTBOUND);
        assert_eq!((e2.family, e2.protocol), (4, 6));
        assert_eq!(e2.local_addr, local);
        assert_eq!(e2.remote_addr, remote);
        assert_eq!((e2.local_port, e2.remote_port), (51234, 443));
        assert_eq!(format_address(4, &e2.remote_addr), "93.184.216.34");
        assert!(NetFlowEvent::deserialize(&buff[..buff.len() - 1]).is_none());
    }

    #[test]
    fn round_trip_v6() {
        let mut remote = [0u8; 16];
        remote[0] = 0x20;
        remote[1] = 0x01;
        remote[15] = 0x01;
        let e1 = NetFlowEvent::new(
            7,
            session(),
            DIRECTION_OUTBOUND,
            6,
            17,
            [0u8; 16],
            remote,
            53,
            53,
        );
        let buff = e1.serialize().unwrap();
        let e2 = NetFlowEvent::deserialize(&buff).unwrap();
        assert_eq!((e2.family, e2.protocol), (6, 17));
        assert_eq!(e2.remote_addr, remote);
        assert_eq!(format_address(6, &e2.remote_addr), "2001:0:0:0:0:0:0:1");
    }

    #[test]
    fn address_format_is_stable() {
        assert_eq!(
            format_address(4, &[127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            "127.0.0.1"
        );
    }

    #[test]
    fn string_is_used_for_debug() {
        let e = NetFlowEvent::new(1, session(), 0, 4, 6, [0; 16], [0; 16], 1, 2);
        assert!(format!("{e:?}").contains("NetFlowEvent"));
        assert_eq!(e.pid().to_string(), "1");
    }
}
