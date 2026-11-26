//! Injects the communication-port shared key as `PORT_KEY` into the crate.
//!
//! The key is taken from `RAMON_PORT_KEY` (64 hex chars) or, failing that, from a gitignored
//! `.portkey` at the repository root; if neither exists a random key is generated and written to
//! `.portkey` so the driver and the client of the next build agree on it. The key is emitted into
//! `$OUT_DIR/port_key.rs`, never into the source tree, so it cannot leak through the public mirror.
use std::{env, fs, path::PathBuf};

#[link(name = "advapi32")]
extern "system" {
    // RtlGenRandom: the OS CSPRNG, available in the host process that runs the build script
    fn SystemFunction036(buffer: *mut u8, length: u32) -> u8;
}

fn main() {
    println!("cargo:rerun-if-env-changed=RAMON_PORT_KEY");
    let root =
        PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).parent().unwrap().to_path_buf();
    let key_path = root.join(".portkey");
    println!("cargo:rerun-if-changed={}", key_path.display());

    let hex = match env::var("RAMON_PORT_KEY") {
        Ok(value) if !value.trim().is_empty() => value.trim().to_string(),
        _ => match fs::read_to_string(&key_path) {
            Ok(value) if !value.trim().is_empty() => value.trim().to_string(),
            _ => {
                let key = random_key();
                let hex: String = key.iter().map(|byte| format!("{byte:02x}")).collect();
                fs::write(&key_path, &hex).expect("write .portkey");
                println!(
                    "cargo:warning=generated a new communication-port key at {}",
                    key_path.display()
                );
                hex
            },
        },
    };
    let bytes = parse_key(&hex);
    let source = render(&bytes);
    fs::write(PathBuf::from(env::var("OUT_DIR").unwrap()).join("port_key.rs"), source)
        .expect("write port_key.rs");
}

fn parse_key(hex: &str) -> [u8; 32] {
    let hex = hex.trim();
    assert_eq!(hex.len(), 64, "RAMON_PORT_KEY must be 64 hex chars (32 bytes), got {}", hex.len());
    let mut key = [0u8; 32];
    for (i, byte) in key.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .unwrap_or_else(|_| panic!("RAMON_PORT_KEY is not hex: {hex}"));
    }
    key
}

fn render(key: &[u8; 32]) -> String {
    let mut source = String::from("pub const PORT_KEY: [u8; 32] = [");
    for byte in key {
        source.push_str(&format!("0x{byte:02x}, "));
    }
    source.push_str("];\n");
    source
}

fn random_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    let ok = unsafe { SystemFunction036(key.as_mut_ptr(), key.len() as u32) };
    assert!(ok != 0, "RtlGenRandom (SystemFunction036) failed");
    key
}
