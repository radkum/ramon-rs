use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::mem;

use crate::{event::EventHeader, utils::align};

/// `None` when `bytes` is too short for the encoded value.
pub trait Deserializer {
    fn from_blob(bytes: &[u8]) -> Option<Self>
    where
        Self: Sized;
}

impl Deserializer for EventHeader {
    fn from_blob(bytes: &[u8]) -> Option<Self> {
        let event_class = u32::from_blob(bytes)?;
        let event_size = u32::from_blob(bytes.get(4..)?)?;
        Some(Self {
            event_class,
            event_size,
        })
    }
}

impl Deserializer for u32 {
    fn from_blob(bytes: &[u8]) -> Option<Self> {
        Some(u32::from_le_bytes(bytes.get(..4)?.try_into().ok()?))
    }
}

impl Deserializer for u64 {
    fn from_blob(bytes: &[u8]) -> Option<Self> {
        Some(u64::from_le_bytes(bytes.get(..8)?.try_into().ok()?))
    }
}

impl Deserializer for String {
    fn from_blob(bytes: &[u8]) -> Option<Self> {
        Some(String::from_blob_with_size(bytes)?.0)
    }
}

impl Deserializer for Vec<u8> {
    fn from_blob(bytes: &[u8]) -> Option<Self> {
        Some(Vec::<u8>::from_blob_with_size(bytes)?.0)
    }
}

#[allow(private_bounds)]
pub(crate) trait DeserializerWithSize {
    fn from_blob_with_size(bytes: &[u8]) -> Option<(Self, usize)>
    where
        Self: Sized;
}

impl DeserializerWithSize for String {
    fn from_blob_with_size(bytes: &[u8]) -> Option<(Self, usize)> {
        //string len as u32 and then char array
        let size = u32::from_blob(bytes)? as usize;
        let chars = bytes.get(4..4 + size)?;
        let mut s = String::from_utf8(chars.to_vec()).unwrap_or("Something wrong".to_string());
        if s.ends_with("\0") {
            s.pop();
        }
        Some((s, align(size) as usize + mem::size_of::<u32>()))
    }
}

impl DeserializerWithSize for Vec<u8> {
    fn from_blob_with_size(bytes: &[u8]) -> Option<(Self, usize)> {
        let size = u32::from_blob(bytes)? as usize;
        Some((
            bytes.get(4..4 + size)?.to_vec(),
            size + mem::size_of::<u32>(),
        ))
    }
}
