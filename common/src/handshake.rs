//! Communication-port handshake: the client proves it holds the shared key without sending it.
//!
//! The connect context carries `nonce || HMAC-SHA256(key, nonce)`; the driver recomputes the MAC
//! and compares in constant time. A fresh random nonce per connect makes a captured proof
//! unusable again. Pure Rust, no allocation, so the driver (no_std) and the client share one
//! implementation.
use core::convert::TryInto;

/// Nonce length in the connect context.
pub const NONCE_LEN: usize = 32;
/// HMAC-SHA256 tag length.
pub const MAC_LEN: usize = 32;
/// Full connect-context size: `nonce || mac`.
pub const PROOF_LEN: usize = NONCE_LEN + MAC_LEN;

mod generated {
    include!(concat!(env!("OUT_DIR"), "/port_key.rs"));
}

/// The shared 32-byte key, embedded at build time (see `build.rs`; never committed to source).
pub fn port_key() -> &'static [u8; 32] {
    &generated::PORT_KEY
}

/// Builds a `nonce || mac` proof over `nonce`.
pub fn make_proof(key: &[u8], nonce: &[u8; NONCE_LEN]) -> [u8; PROOF_LEN] {
    let mut proof = [0u8; PROOF_LEN];
    proof[..NONCE_LEN].copy_from_slice(nonce);
    proof[NONCE_LEN..].copy_from_slice(&hmac_sha256(key, nonce));
    proof
}

/// The nonce carried by a proof.
pub fn proof_nonce(proof: &[u8; PROOF_LEN]) -> &[u8; NONCE_LEN] {
    proof[..NONCE_LEN].try_into().unwrap()
}

/// True when `proof` is `PROOF_LEN` bytes and its MAC matches `key` over the embedded nonce.
pub fn verify_proof(key: &[u8], proof: &[u8]) -> bool {
    if proof.len() != PROOF_LEN {
        return false;
    }
    let proof: &[u8; PROOF_LEN] = proof.try_into().unwrap();
    let mac: &[u8; MAC_LEN] = proof[NONCE_LEN..].try_into().unwrap();
    constant_time_eq(mac, &hmac_sha256(key, proof_nonce(proof)))
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

/// SHA-256 (FIPS 180-4), streaming so HMAC can hash `ipad || msg` without allocating.
pub struct Sha256 {
    state: [u32; 8],
    buffer: [u8; 64],
    buffered: usize,
    length: u64,
}

impl Sha256 {
    pub fn new() -> Self {
        Self {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            buffer: [0u8; 64],
            buffered: 0,
            length: 0,
        }
    }

    pub fn update(&mut self, mut data: &[u8]) {
        self.length = self.length.wrapping_add(data.len() as u64);
        if self.buffered > 0 {
            let take = (64 - self.buffered).min(data.len());
            self.buffer[self.buffered..self.buffered + take].copy_from_slice(&data[..take]);
            self.buffered += take;
            data = &data[take..];
            if self.buffered < 64 {
                return;
            }
            compress(&mut self.state, &self.buffer);
            self.buffered = 0;
        }
        let mut chunks = data.chunks_exact(64);
        for chunk in &mut chunks {
            compress(&mut self.state, chunk.try_into().unwrap());
        }
        let rest = chunks.remainder();
        self.buffer[..rest.len()].copy_from_slice(rest);
        self.buffered = rest.len();
    }

    pub fn finalize(mut self) -> [u8; 32] {
        let bits = self.length.wrapping_mul(8);
        let mut pad = [0u8; 72];
        pad[0] = 0x80;
        let pad_len = if self.buffered < 56 { 56 - self.buffered } else { 120 - self.buffered };
        self.update(&pad[..pad_len]);
        self.update(&bits.to_be_bytes());
        let mut out = [0u8; 32];
        for (i, word) in self.state.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(data);
    hash.finalize()
}

/// HMAC-SHA256 (RFC 2104).
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut block = [0u8; 64];
    if key.len() > 64 {
        block[..32].copy_from_slice(&sha256(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut inner = Sha256::new();
    let mut ipad = [0u8; 64];
    let mut opad = [0u8; 64];
    for i in 0..64 {
        ipad[i] = block[i] ^ 0x36;
        opad[i] = block[i] ^ 0x5c;
    }
    inner.update(&ipad);
    inner.update(message);
    let inner = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(&opad);
    outer.update(&inner);
    outer.finalize()
}

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

fn compress(state: &mut [u32; 8], block: &[u8; 64]) {
    let mut w = [0u32; 64];
    for i in 0..16 {
        w[i] = u32::from_be_bytes(block[i * 4..i * 4 + 4].try_into().unwrap());
    }
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
    }
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    for i in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ ((!e) & g);
        let t1 = h.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(maj);
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }
    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> [u8; 32] {
        hex::decode(s).unwrap().try_into().unwrap()
    }

    #[test]
    fn sha256_vectors() {
        assert_eq!(
            sha256(b""),
            unhex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        );
        assert_eq!(
            sha256(b"abc"),
            unhex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        );
        // multi-block (> 64 bytes) exercises the streaming path
        assert_eq!(
            sha256(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            unhex("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1")
        );
    }

    #[test]
    fn hmac_sha256_vectors() {
        // RFC 4231 test case 1
        let key = [0x0bu8; 20];
        assert_eq!(
            hmac_sha256(&key, b"Hi There"),
            unhex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
        );
        // RFC 4231 test case 2
        assert_eq!(
            hmac_sha256(b"Jefe", b"what do ya want for nothing?"),
            unhex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
        );
        // RFC 4231 test case 6: key longer than the block, hashed first
        let key = [0xaau8; 131];
        let msg = b"Test Using Larger Than Block-Size Key - Hash Key First";
        assert_eq!(
            hmac_sha256(&key, msg),
            unhex("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54")
        );
    }

    #[test]
    fn proof_round_trip() {
        let key = [7u8; 32];
        let nonce = [9u8; NONCE_LEN];
        let proof = make_proof(&key, &nonce);
        assert_eq!(proof.len(), PROOF_LEN);
        assert_eq!(proof_nonce(&proof), &nonce);
        assert!(verify_proof(&key, &proof));
        assert!(!verify_proof(&[8u8; 32], &proof));
        assert!(!verify_proof(&key, &proof[..PROOF_LEN - 1]));
        let mut tampered = proof;
        tampered[NONCE_LEN] ^= 1;
        assert!(!verify_proof(&key, &tampered));
    }
}
