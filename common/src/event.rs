use alloc::{collections::TryReserveError, vec::Vec};
use core::{fmt::Formatter, mem};

pub mod canary;
pub mod file_create;
pub mod file_set_information;
pub mod file_telemetry;
pub mod guardrail_blocked;
pub mod handle_open;
pub mod image_load;
pub mod mirage_redirect;
pub mod mota;
pub mod net_flow;
pub mod process_create;
pub mod registry_set_value;
pub mod session_assigned;

pub use file_create::FileCreateEvent;
pub use file_telemetry::FileTelemetryEvent;
pub use mota::MotaEvent;

#[cfg(feature = "client")]
use crate::deserializer::Deserializer;
use crate::{cleaning_info::CleaningInfoTrait, serializer::Serializer, utils::try_extend};

#[cfg(feature = "client")]
pub fn get_event_type(bytes: &[u8]) -> Option<u32> {
    u32::from_blob(bytes)
}

#[derive(Debug, Copy, Clone)]
pub struct Pid(pub u32);

impl core::fmt::Display for Pid {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

pub trait Event: Serializer + CleaningInfoTrait {
    const EVENT_CLASS: u32;

    fn blob_with_header_size(&self) -> usize {
        EventHeader::EVENT_HEADER_SIZE + self.blob_size() as usize
    }

    fn serialize(&self) -> Result<Vec<u8>, TryReserveError> {
        let mut v = Vec::new();
        v.try_reserve_exact(self.blob_with_header_size())?;

        let file_event_blob = self.to_blob()?;
        let header = EventHeader::new(Self::EVENT_CLASS, file_event_blob.len() as u32);
        try_extend(&mut v, &header.to_blob()?)?;

        try_extend(&mut v, &file_event_blob)?;
        Ok(v)
    }
    #[cfg(feature = "client")]
    fn deserialize(bytes: &[u8]) -> Option<Self>
    where
        Self: Sized + Deserializer,
    {
        let header = EventHeader::deserialize(bytes)?;
        if header.event_class != Self::EVENT_CLASS {
            return None;
        }
        let beg = EventHeader::EVENT_HEADER_SIZE;
        let end = EventHeader::EVENT_HEADER_SIZE + header.event_size as usize;
        Self::from_blob(bytes.get(beg..end)?)
    }
}

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub(crate) struct EventHeader {
    pub event_class: u32,
    pub event_size: u32,
}

impl EventHeader {
    const EVENT_HEADER_SIZE: usize = mem::size_of::<EventHeader>();

    #[cfg(feature = "client")]
    pub fn deserialize(bytes: &[u8]) -> Option<Self> {
        EventHeader::from_blob(bytes)
    }

    pub fn new(event_class: u32, event_size: u32) -> Self {
        Self {
            event_class,
            event_size,
        }
    }

    pub fn header_struct_size() -> usize {
        Self::EVENT_HEADER_SIZE
    }

    #[allow(dead_code)]
    pub fn as_ptr(&self) -> *const u8 {
        self as *const Self as *const u8
    }

    #[allow(dead_code)]
    pub fn as_ref(&self) -> &Self {
        self
    }
}
