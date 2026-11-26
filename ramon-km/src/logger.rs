//! `log` backend that prints through `DbgPrintEx` from a fixed stack buffer (no allocation,
//! safe on the load/unload path). Messages longer than 512 bytes are truncated.
use core::fmt::{self, Write};

use log::{LevelFilter, Metadata, Record, SetLoggerError};

extern "C" {
    fn DbgPrintEx(component_id: u32, level: u32, format: *const u8, ...) -> u32;
}

const MESSAGE_SIZE: usize = 512;

static LOGGER: KernelLogger = KernelLogger;

/// DbgPrintEx logger without heap allocation; messages longer than MESSAGE_SIZE are truncated.
pub(crate) struct KernelLogger;

impl KernelLogger {
    pub(crate) fn init(level: LevelFilter) -> Result<(), SetLoggerError> {
        log::set_logger(&LOGGER).map(|()| log::set_max_level(level))
    }
}

struct StackBuffer {
    buf: [u8; MESSAGE_SIZE],
    len: usize,
}

impl Write for StackBuffer {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        // keep the last byte for NUL
        let n = s.len().min(MESSAGE_SIZE - 1 - self.len);
        self.buf[self.len..self.len + n].copy_from_slice(&s.as_bytes()[..n]);
        self.len += n;
        Ok(())
    }
}

impl log::Log for KernelLogger {
    fn enabled(&self, _metadata: &Metadata) -> bool {
        true
    }

    fn log(&self, record: &Record) {
        let mut message = StackBuffer { buf: [0; MESSAGE_SIZE], len: 0 };
        let _ = writeln!(message, "{:<5} [{}] {}", record.level(), record.target(), record.args());
        // message goes as %s argument: a '%' in a path must not be parsed as a format spec
        unsafe { DbgPrintEx(0, 0, c"%s".as_ptr() as *const u8, message.buf.as_ptr()) };
    }

    fn flush(&self) {}
}
