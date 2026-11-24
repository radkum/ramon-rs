use alloc::{collections::TryReserveError, string::String, vec::Vec};
use core::mem;

use crate::{
    event::EventHeader,
    utils::{align, try_extend, try_filled},
};

pub trait Serializer {
    fn blob_size(&self) -> u32;
    fn to_blob(&self) -> Result<Vec<u8>, TryReserveError>;
}

impl Serializer for String {
    fn blob_size(&self) -> u32 {
        //string len as u32 and then char array
        const NULL_CHAR_LEN: usize = 1;
        align(self.len() + NULL_CHAR_LEN) + mem::size_of::<u32>() as u32
    }

    fn to_blob(&self) -> Result<Vec<u8>, TryReserveError> {
        let v_len = self.blob_size() as usize;
        let mut v = try_filled(v_len, 0u8)?;

        let u32_len = self.len() as u32 + 1;
        v[0..mem::size_of::<u32>()].copy_from_slice(&u32_len.to_le_bytes());

        //null at the end of string is already there: v is zero-filled
        let path_offset = mem::size_of::<u32>();
        v[path_offset..path_offset + self.len()].copy_from_slice(self.as_bytes());
        Ok(v)
    }
}

impl Serializer for EventHeader {
    fn blob_size(&self) -> u32 {
        align(Self::header_struct_size())
    }

    fn to_blob(&self) -> Result<Vec<u8>, TryReserveError> {
        let mut v = try_filled(self.blob_size() as usize, 0u8)?;

        let u32_size = mem::size_of::<u32>();

        v[0..u32_size].copy_from_slice(&self.event_class.to_le_bytes());
        v[u32_size..2 * u32_size].copy_from_slice(&self.event_size.to_le_bytes());
        Ok(v)
    }
}

impl Serializer for u32 {
    fn blob_size(&self) -> u32 {
        4
    }

    fn to_blob(&self) -> Result<Vec<u8>, TryReserveError> {
        let mut v = try_filled(self.blob_size() as usize, 0u8)?;
        v[0..mem::size_of::<u32>()].copy_from_slice(&self.to_le_bytes());
        Ok(v)
    }
}

impl Serializer for u64 {
    fn blob_size(&self) -> u32 {
        8
    }

    fn to_blob(&self) -> Result<Vec<u8>, TryReserveError> {
        let mut v = try_filled(self.blob_size() as usize, 0u8)?;
        v[0..mem::size_of::<u64>()].copy_from_slice(&self.to_le_bytes());
        Ok(v)
    }
}

impl Serializer for Vec<u8> {
    fn blob_size(&self) -> u32 {
        //string len as u32 and then char array
        align(self.len()) + mem::size_of::<u32>() as u32
    }

    fn to_blob(&self) -> Result<Vec<u8>, TryReserveError> {
        let mut v = u32::to_blob(&(self.len() as u32))?;

        try_extend(&mut v, self)?;
        Ok(v)
    }
}
