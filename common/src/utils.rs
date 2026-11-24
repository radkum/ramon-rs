use alloc::{collections::TryReserveError, string::String, vec::Vec};
use core::mem;

#[cfg(feature = "client")]
use sha2::Digest;

pub const SHA256_LEN: usize = 32;
pub type Sha256Buff = [u8; SHA256_LEN];

#[cfg(feature = "client")]
use thiserror_no_std::Error;

#[cfg(feature = "client")]
#[derive(Error, Debug)]
pub enum ShaError {
    #[error("Sha string must have 32 chars not {string_len}")]
    IncorrectStringLen { string_len: usize },
    #[error("ToHex error: {0}")]
    ToHexError(#[from] hex::FromHexError),
}

#[cfg(feature = "client")]
pub fn sha256_from_vec(v: Vec<u8>) -> Sha256Buff {
    let mut hasher = sha2::Sha256::new();
    hasher.update(v);

    let mut checksum_buf = Sha256Buff::default();
    checksum_buf.copy_from_slice(&hasher.finalize()[..]);
    checksum_buf
}

#[cfg(feature = "client")]
pub fn sha256_from_bytes(v: &[u8]) -> Sha256Buff {
    sha256_from_vec(v.to_vec())
}

#[cfg(feature = "client")]
#[allow(dead_code)]
pub fn sha256_from_vec_of_vec(vec: Vec<Vec<u8>>) -> Sha256Buff {
    let mut hasher = sha2::Sha256::new();

    for v in vec {
        hasher.update(v);
    }

    let mut checksum_buf = Sha256Buff::default();
    checksum_buf.copy_from_slice(&hasher.finalize()[..]);
    checksum_buf
}

#[cfg(feature = "client")]
pub fn sha256_from_string(s: String) -> Sha256Buff {
    let mut hasher = sha2::Sha256::new();
    hasher.update(s.as_bytes());

    let mut checksum_buf = Sha256Buff::default();
    checksum_buf.copy_from_slice(&hasher.finalize()[..]);
    checksum_buf
}

#[cfg(feature = "client")]
pub fn sha256_from_sha_string(s: &str) -> Result<Sha256Buff, ShaError> {
    let mut sha = Sha256Buff::default();
    let v = hex::decode(s)?;

    if v.len() != SHA256_LEN {
        return Err(ShaError::IncorrectStringLen {
            string_len: v.len(),
        });
    }
    sha.copy_from_slice(&v);
    Ok(sha)
}

#[cfg(feature = "client")]
pub fn convert_sha256_to_string(sha: &Sha256Buff) -> String {
    hex::encode_upper(sha)
}

pub fn align(size: usize) -> u32 {
    //const ALIGNMENT: usize = mem::size_of::<usize>();
    const ALIGNMENT: usize = mem::size_of::<u32>();
    if size.is_multiple_of(ALIGNMENT) {
        size as u32
    } else {
        (size + (ALIGNMENT - size % ALIGNMENT)) as u32
    }
}

// Fallible helpers: the driver builds alloc with no_global_oom_handling, which removes push/extend/clone/to_vec.
pub fn try_extend<T: Copy>(v: &mut Vec<T>, items: &[T]) -> Result<(), TryReserveError> {
    v.try_reserve(items.len())?;
    let len = v.len();
    for (dst, item) in v.spare_capacity_mut().iter_mut().zip(items) {
        dst.write(*item);
    }
    unsafe { v.set_len(len + items.len()) };
    Ok(())
}

pub fn try_to_vec<T: Copy>(items: &[T]) -> Result<Vec<T>, TryReserveError> {
    let mut v = Vec::new();
    try_extend(&mut v, items)?;
    Ok(v)
}

pub fn try_filled<T: Copy>(len: usize, value: T) -> Result<Vec<T>, TryReserveError> {
    let mut v = Vec::new();
    v.try_reserve_exact(len)?;
    v.spare_capacity_mut()[..len].fill(core::mem::MaybeUninit::new(value));
    unsafe { v.set_len(len) };
    Ok(v)
}

pub fn try_to_string(s: &str) -> Result<String, TryReserveError> {
    let mut string = String::new();
    try_push_str(&mut string, s)?;
    Ok(string)
}

pub fn try_push_str(string: &mut String, s: &str) -> Result<(), TryReserveError> {
    // appending valid UTF-8 keeps the string valid
    try_extend(unsafe { string.as_mut_vec() }, s.as_bytes())
}
