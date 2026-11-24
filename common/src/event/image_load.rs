#[cfg(feature = "client")]
use alloc::format;
use alloc::{collections::TryReserveError, string::String, vec::Vec};
use core::mem;

#[cfg(feature = "client")]
use serde::{Deserialize, Serialize};

#[cfg(feature = "client")]
use super::Deserializer;
use super::{Event, Serializer};
use crate::{cleaning_info::CleaningInfoTrait, event::Pid, utils::try_extend};
#[cfg(feature = "client")]
use crate::{
    hasher::MemberHasher,
    utils::{sha256_from_bytes, Sha256Buff},
};

#[derive(Debug)]
pub struct ImageLoadEvent {
    pid: u32,
    image_base: u64,
    image_size: u64,
    path: String,
}

#[cfg(feature = "client")]
#[derive(Debug, Serialize, Deserialize)]
pub struct YamlImageLoadEvent {
    pid: Option<u32>,
    image_base: Option<u64>,
    image_size: Option<u64>,
    path: Option<String>,
}

#[cfg(feature = "client")]
impl From<YamlImageLoadEvent> for ImageLoadEvent {
    fn from(yaml: YamlImageLoadEvent) -> Self {
        Self {
            pid: yaml.pid.unwrap_or_default(),
            image_base: yaml.image_base.unwrap_or_default(),
            image_size: yaml.image_size.unwrap_or_default(),
            path: yaml.path.unwrap_or_default(),
        }
    }
}

impl ImageLoadEvent {
    pub fn new(pid: u32, image_base: u64, image_size: u64, path: String) -> Self {
        Self {
            pid,
            image_base,
            image_size,
            path,
        }
    }

    #[cfg(feature = "client")]
    pub fn pid(&self) -> u32 {
        self.pid
    }

    #[cfg(feature = "client")]
    pub fn image_base(&self) -> u64 {
        self.image_base
    }

    #[cfg(feature = "client")]
    pub fn image_size(&self) -> u64 {
        self.image_size
    }

    #[cfg(feature = "client")]
    pub fn path(&self) -> &str {
        &self.path
    }
}

impl Event for ImageLoadEvent {
    //"DLL " as u32-> 44 4C 4C 20
    const EVENT_CLASS: u32 = 0x204C4C44;
}

impl Serializer for ImageLoadEvent {
    fn blob_size(&self) -> u32 {
        mem::size_of::<u32>() as u32
            + mem::size_of::<u64>() as u32
            + mem::size_of::<u64>() as u32
            + self.path.blob_size()
    }

    fn to_blob(&self) -> Result<Vec<u8>, TryReserveError> {
        let mut v = Vec::new();
        let v_len = self.blob_size() as usize;
        v.try_reserve_exact(v_len)?;

        try_extend(&mut v, &self.pid.to_blob()?)?;
        try_extend(&mut v, &self.image_base.to_blob()?)?;
        try_extend(&mut v, &self.image_size.to_blob()?)?;
        try_extend(&mut v, &self.path.to_blob()?)?;

        Ok(v)
    }
}

#[cfg(feature = "client")]
impl Deserializer for ImageLoadEvent {
    fn from_blob(bytes: &[u8]) -> Option<Self> {
        let pid = u32::from_blob(bytes)?;
        let bytes = bytes.get(4..)?;

        let image_base = u64::from_blob(bytes)?;
        let bytes = bytes.get(8..)?;

        let image_size = u64::from_blob(bytes)?;
        let bytes = bytes.get(8..)?;

        let path = String::from_blob(bytes)?;
        Some(Self {
            pid,
            image_base,
            image_size,
            path,
        })
    }
}

#[cfg(feature = "client")]
impl MemberHasher for ImageLoadEvent {
    const EVENT_NAME: &'static str = "ImageLoad";

    fn hash_members(&self) -> Vec<Sha256Buff> {
        let mut v = Vec::new();

        if self.pid != 0 {
            let pid = format!("{}+{}+{}", Self::EVENT_NAME, "pid", self.pid);
            v.push(sha256_from_bytes(pid.as_bytes()));
        }

        if self.image_base != 0 {
            let image_base = format!("{}+{}+{}", Self::EVENT_NAME, "image_base", self.image_base);
            v.push(sha256_from_bytes(image_base.as_bytes()));
        }

        if self.image_size != 0 {
            let image_size = format!("{}+{}+{}", Self::EVENT_NAME, "image_size", self.image_size);
            v.push(sha256_from_bytes(image_size.as_bytes()));
        }

        if !self.path.is_empty() {
            let path = format!("{}+{}+{}", Self::EVENT_NAME, "path", self.path);
            v.push(sha256_from_bytes(path.as_bytes()));
        }
        v
    }
}

impl CleaningInfoTrait for ImageLoadEvent {
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
        let e1 = ImageLoadEvent::new(123, 234, 345, "elo mordo".to_string());
        let event_buff = e1.serialize().unwrap();

        let event_type = get_event_type(event_buff.as_slice());
        assert_eq!(event_type, Some(ImageLoadEvent::EVENT_CLASS));

        let e2 = ImageLoadEvent::deserialize(event_buff.as_slice()).unwrap();
        assert_eq!(e1.pid, e2.pid);
        assert_eq!(e1.image_size, e2.image_size);
        assert_eq!(e1.image_base, e2.image_base);
        assert_eq!(e1.path, e2.path);
    }
}
