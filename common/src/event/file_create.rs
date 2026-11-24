#[cfg(feature = "client")]
use alloc::format;
use alloc::{collections::TryReserveError, string::String, vec::Vec};

#[cfg(feature = "client")]
use serde::{Deserialize, Serialize};

#[cfg(feature = "client")]
use super::Deserializer;
use super::{Event, Serializer};
use crate::{cleaning_info::CleaningInfoTrait, event::Pid};
#[cfg(feature = "client")]
use crate::{
    hasher::MemberHasher,
    utils::{sha256_from_bytes, Sha256Buff},
};

#[derive(Debug)]
pub struct FileCreateEvent {
    //header: EventHeader,
    path: String,
}

#[cfg(feature = "client")]
#[derive(Debug, Serialize, Deserialize)]
pub struct YamlFileCreateEvent {
    path: Option<String>,
}

#[cfg(feature = "client")]
impl From<YamlFileCreateEvent> for FileCreateEvent {
    fn from(yaml: YamlFileCreateEvent) -> Self {
        Self {
            path: yaml.path.unwrap_or_default(),
        }
    }
}

impl FileCreateEvent {
    pub fn new(path: String) -> Self {
        Self { path }
    }

    #[cfg(feature = "client")]
    pub fn get_path(&self) -> String {
        self.path.clone()
    }
}
impl Event for FileCreateEvent {
    //"CRE " as u32-> 43 52 45 20
    const EVENT_CLASS: u32 = 0x20455243;
}

impl Serializer for FileCreateEvent {
    fn blob_size(&self) -> u32 {
        self.path.blob_size()
    }

    fn to_blob(&self) -> Result<Vec<u8>, TryReserveError> {
        self.path.to_blob()
    }
}

#[cfg(feature = "client")]
impl Deserializer for FileCreateEvent {
    fn from_blob(bytes: &[u8]) -> Option<Self> {
        let path = String::from_blob(bytes)?;
        Some(Self { path })
    }
}

#[cfg(feature = "client")]
impl MemberHasher for FileCreateEvent {
    const EVENT_NAME: &'static str = "FileCreate";

    fn hash_members(&self) -> Vec<Sha256Buff> {
        let mut v = Vec::new();

        if !self.path.is_empty() {
            let s = format!("{}+{}+{}", Self::EVENT_NAME, "path", self.path);
            v.push(sha256_from_bytes(s.as_bytes()));
        }

        v
    }
}

impl CleaningInfoTrait for FileCreateEvent {
    fn get_pid(&self) -> Pid {
        todo!()
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
        let e1 = FileCreateEvent::new("elo mordo".to_string());
        let event_buff = e1.serialize().unwrap();

        let event_type = get_event_type(event_buff.as_slice());
        assert_eq!(event_type, Some(FileCreateEvent::EVENT_CLASS));

        let e2 = FileCreateEvent::deserialize(event_buff.as_slice()).unwrap();
        assert_eq!(e1.path, e2.path);
    }
}
