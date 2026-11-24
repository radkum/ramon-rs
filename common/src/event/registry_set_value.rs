use alloc::{collections::TryReserveError, string::String, vec::Vec};
use core::mem;

#[cfg(feature = "client")]
use serde::{Deserialize, Serialize};

#[cfg(feature = "client")]
use super::Deserializer;
use super::{Event, Serializer};
#[cfg(feature = "client")]
use crate::enums::RegType;
use crate::{cleaning_info::CleaningInfoTrait, event::Pid, utils::try_extend};
#[cfg(feature = "client")]
use crate::{
    deserializer::DeserializerWithSize,
    hasher::{member_to_hash, MemberHasher},
    utils::Sha256Buff,
};

#[derive(Debug)]
pub struct RegistrySetValueEvent {
    pid: u32,
    tid: u32,
    key_name: String,
    value_name: String,
    data_type: u32,
    data: Vec<u8>,
}

#[cfg(feature = "client")]
#[derive(Debug, Serialize, Deserialize)]
pub struct YamlRegistrySetValueEvent {
    pub pid: Option<u32>,
    pub tid: Option<u32>,
    pub key_name: Option<String>,
    pub value_name: Option<String>,
    pub data_type: Option<u32>,
    //pub data: Option<Vec<u8>>,
    pub data: Option<String>,
}

#[cfg(feature = "client")]
impl From<YamlRegistrySetValueEvent> for RegistrySetValueEvent {
    fn from(yaml: YamlRegistrySetValueEvent) -> Self {
        Self {
            pid: yaml.pid.unwrap_or_default(),
            tid: yaml.tid.unwrap_or_default(),
            key_name: yaml.key_name.unwrap_or_default(),
            value_name: yaml.value_name.unwrap_or_default(),
            data_type: yaml.data_type.unwrap_or_default(),
            data: yaml.data.unwrap_or_default().into(),
        }
    }
}

impl RegistrySetValueEvent {
    pub fn new(
        pid: u32,
        tid: u32,
        key_name: String,
        value_name: String,
        data_type: u32,
        data: Vec<u8>,
    ) -> Self {
        Self {
            pid,
            tid,
            key_name,
            value_name,
            data_type,
            data,
        }
    }

    #[cfg(feature = "client")]
    pub fn pid(&self) -> u32 {
        self.pid
    }

    #[cfg(feature = "client")]
    pub fn tid(&self) -> u32 {
        self.tid
    }

    #[cfg(feature = "client")]
    pub fn key_name(&self) -> &str {
        &self.key_name
    }

    #[cfg(feature = "client")]
    pub fn value_name(&self) -> &str {
        &self.value_name
    }

    #[cfg(feature = "client")]
    pub fn data_type(&self) -> u32 {
        self.data_type
    }

    #[cfg(feature = "client")]
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    #[cfg(feature = "client")]
    pub fn data_as_string(&self) -> Option<String> {
        //todo: support more types
        let data_type = RegType::from(self.data_type);
        if !data_type.is_string() {
            return None;
        }

        let data_u16 = self
            .data
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .take_while(|&e| e != 0);
        Some(
            char::decode_utf16(data_u16)
                .map(|c| c.unwrap_or(char::REPLACEMENT_CHARACTER))
                .collect(),
        )
    }

    #[cfg(feature = "client")]
    pub fn data_as_string2(&self) -> Option<String> {
        //todo: support more types
        let data_type = RegType::from(self.data_type);
        if !data_type.is_string() {
            return None;
        }

        let data = self.data.clone();

        let mut s = String::new();
        s.reserve(data.len());
        for e in data {
            if e == 0 {
                break;
            }
            s.push(e as char);
        }
        Some(s)
    }
}

impl Event for RegistrySetValueEvent {
    //"REG " as u32-> 52 45 47 20
    const EVENT_CLASS: u32 = 0x20474552;
}

impl Serializer for RegistrySetValueEvent {
    fn blob_size(&self) -> u32 {
        mem::size_of::<u32>() as u32
            + mem::size_of::<u32>() as u32
            + self.key_name.blob_size()
            + mem::size_of::<u32>() as u32
            + self.value_name.blob_size()
            + self.data.blob_size()
    }

    fn to_blob(&self) -> Result<Vec<u8>, TryReserveError> {
        let mut v = Vec::new();
        let v_len = self.blob_size() as usize;
        v.try_reserve_exact(v_len)?;

        try_extend(&mut v, &self.pid.to_blob()?)?;
        try_extend(&mut v, &self.tid.to_blob()?)?;
        try_extend(&mut v, &self.key_name.to_blob()?)?;
        try_extend(&mut v, &self.value_name.to_blob()?)?;
        try_extend(&mut v, &self.data_type.to_blob()?)?;
        try_extend(&mut v, &self.data.to_blob()?)?;

        Ok(v)
    }
}

#[cfg(feature = "client")]
impl Deserializer for RegistrySetValueEvent {
    fn from_blob(bytes: &[u8]) -> Option<Self> {
        let pid = u32::from_blob(bytes)?;
        let bytes = bytes.get(4..)?;

        let tid = u32::from_blob(bytes)?;
        let bytes = bytes.get(4..)?;

        let (key_name, shift) = String::from_blob_with_size(bytes)?;
        let bytes = bytes.get(shift..)?;

        let (value_name, shift) = String::from_blob_with_size(bytes)?;
        let bytes = bytes.get(shift..)?;

        let data_type = u32::from_blob(bytes)?;
        let bytes = bytes.get(4..)?;

        let data = Vec::<u8>::from_blob(bytes)?;

        Some(Self {
            pid,
            tid,
            key_name,
            value_name,
            data_type,
            data,
        })
    }
}

#[cfg(feature = "client")]
impl MemberHasher for RegistrySetValueEvent {
    const EVENT_NAME: &'static str = "RegSetValue";

    fn hash_members(&self) -> Vec<Sha256Buff> {
        let mut v = Vec::new();

        if self.pid != 0 {
            let pid = member_to_hash(Self::EVENT_NAME, "pid", self.pid);
            v.push(pid);
        }

        if self.tid != 0 {
            let tid = member_to_hash(Self::EVENT_NAME, "tid", self.tid);
            v.push(tid);
        }

        if !self.key_name.is_empty() {
            let key_name = member_to_hash(Self::EVENT_NAME, "key_name", self.key_name.clone());
            v.push(key_name);
        }

        if !self.value_name.is_empty() {
            let value_name =
                member_to_hash(Self::EVENT_NAME, "value_name", self.value_name.clone());
            v.push(value_name);
        }

        if self.data_type != 0 {
            let data_type = member_to_hash(Self::EVENT_NAME, "data_type", self.data_type);
            v.push(data_type);
        }

        //todo: parse not only strings
        if let Some(data) = self.data_as_string() {
            log::debug!("data_as_string: {}", data);
            if !data.is_empty() {
                let data = member_to_hash(Self::EVENT_NAME, "data", data.clone());
                v.push(data);
            }
        }
        v
    }
}

impl CleaningInfoTrait for RegistrySetValueEvent {
    fn get_pid(&self) -> Pid {
        Pid(self.pid)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use alloc::{string::ToString, vec};

    use super::*;
    use crate::event::get_event_type;

    #[test]
    fn simple() {
        let e1 = RegistrySetValueEvent::new(
            123,
            234,
            "key name".to_string(),
            "value_name".to_string(),
            345,
            vec![1, 8, 7, 4],
        );
        let event_buff = e1.serialize().unwrap();

        std::println!("{e1:?}");
        let event_type = get_event_type(event_buff.as_slice());
        assert_eq!(event_type, Some(RegistrySetValueEvent::EVENT_CLASS));

        let e2 = RegistrySetValueEvent::deserialize(event_buff.as_slice()).unwrap();
        std::println!("{e2:?}");
        assert_eq!(e1.pid, e2.pid);
        assert_eq!(e1.tid, e2.tid);
        assert_eq!(e1.key_name, e2.key_name);
        assert_eq!(e1.value_name, e2.value_name);
        assert_eq!(e1.data_type, e2.data_type);
        assert_eq!(e1.data, e2.data);
    }

    #[test]
    fn truncated_message_is_rejected() {
        let e1 = RegistrySetValueEvent::new(
            123,
            234,
            "key name".to_string(),
            "value_name".to_string(),
            345,
            vec![1, 8, 7, 4],
        );
        let event_buff = e1.serialize().unwrap();
        for len in 0..event_buff.len() {
            assert!(RegistrySetValueEvent::deserialize(&event_buff[..len]).is_none());
        }
        let mut corrupted = event_buff.clone();
        corrupted[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(RegistrySetValueEvent::deserialize(&corrupted).is_none());
    }

    #[test]
    fn data_as_string_decodes_utf16() {
        let data = "Zażółć\0"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        let e = RegistrySetValueEvent::new(1, 2, "k".to_string(), "v".to_string(), 1, data);
        assert_eq!(e.data_as_string().as_deref(), Some("Zażółć"));
    }

    #[test]
    fn hash_test() {
        let e1 = RegistrySetValueEvent::new(
            123,
            234,
            "key name".to_string(),
            "value_name".to_string(),
            345,
            vec![0x65, 0x6C, 0x6F, 0x20, 0x0, 0x0, 0x0, 0x0],
        );
        let v = e1.hash_members();
        assert_eq!(
            v[0],
            [
                84, 206, 227, 212, 1, 254, 12, 72, 89, 14, 153, 91, 71, 68, 184, 166, 163, 0, 227,
                153, 33, 253, 197, 63, 127, 55, 110, 14, 114, 191, 150, 20
            ]
        );
    }
}
