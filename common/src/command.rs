//! Client to driver commands (FilterSendMessage input buffer).

#[cfg(feature = "client")]
use alloc::vec::Vec;

use ariadne::{ProcessKey, SessionTag};

use crate::event::{
    mota::FileId,
    process_create::{from_of, kind_from_u32, kind_to_u32, SESSION_BLOB_SIZE},
};

/// "ADOP": `child` was started on behalf of `causal` (e.g. through WMI), give it causal's session.
pub const ADOPT: u32 = 0x504F4441;
pub const ADOPT_SIZE: usize = 4 + 2 * (4 + 8);

/// "ADTG": `child` was started by a scheduled task, give it the session the task was registered in.
pub const ADOPT_TAG: u32 = 0x47544441;
pub const ADOPT_TAG_SIZE: usize = 4 + (4 + 8) + 4 + 3 * (4 + 8);

/// "MADD": load one persisted Mark-of-the-Agent marker (FileId + authoring session + path) into the
/// driver's ring, so markers survive a reboot (the client keeps them on disk).
pub const MOTA_ADD: u32 = 0x4444_414D;

/// "GRDL": replace the guardrail path fragments. Body is UTF-8: the tagged-process tier, a NUL,
/// then the any-process tier; each tier holds fragments separated by newlines.
pub const GUARDRAIL: u32 = 0x4C445247;
/// A GUARDRAIL body must fit in this many bytes; the driver copies it onto the stack.
pub const GUARDRAIL_MAX: usize = 1024;

/// "MIRC": configure Mirage. Body is UTF-8: the sensitive path fragments (newline-separated), a NUL,
/// then the decoy suffix appended to a matching path to name its decoy (e.g. `.mirage`).
pub const MIRAGE: u32 = 0x4352_494D;
/// A MIRAGE body must fit in this many bytes; the driver copies it onto the stack.
pub const MIRAGE_MAX: usize = 1024;
/// The largest command body the driver accepts; its stack buffer is sized to this.
pub const COMMAND_MAX: usize = if GUARDRAIL_MAX > MIRAGE_MAX {
    GUARDRAIL_MAX
} else {
    MIRAGE_MAX
};

/// "MIRE": configure Mirage exceptions. A tagged read of a sensitive path that is exempt is served the
/// real file (a legal deploy needs real credentials). Body is UTF-8: the exempt path fragments
/// (newline-separated), a NUL, then the exempt session roots as `pid:create_time` (newline-separated).
pub const MIRAGE_EXCEPT: u32 = 0x4552_494D;

/// Builds a MIRE message (code + path fragments + NUL + session roots).
#[cfg(feature = "client")]
pub fn mirage_except_to_bytes(paths: &[&str], sessions: &[&str]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&MIRAGE_EXCEPT.to_le_bytes());
    v.extend_from_slice(paths.join("\n").as_bytes());
    v.push(0);
    v.extend_from_slice(sessions.join("\n").as_bytes());
    v
}

/// Parses a MIRE message; `None` if the code is wrong, the body is not UTF-8, or the two tiers are not
/// NUL-separated.
pub fn mirage_except_from_bytes(b: &[u8]) -> Option<(&str, &str)> {
    if b.len() < 4 || le_u32(b, 0) != MIRAGE_EXCEPT {
        return None;
    }
    let body = core::str::from_utf8(b.get(4..)?).ok()?;
    body.split_once('\0')
}

/// Builds a GUARDRAIL message (code + body) from the two tiers.
#[cfg(feature = "client")]
pub fn guardrail_to_bytes(tagged: &[&str], any: &[&str]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&GUARDRAIL.to_le_bytes());
    v.extend_from_slice(tagged.join("\n").as_bytes());
    v.push(0);
    v.extend_from_slice(any.join("\n").as_bytes());
    v
}

/// Parses a GUARDRAIL message; `None` if the code is wrong, the body is not UTF-8, or the two
/// tiers are not NUL-separated. The returned tiers are raw (see [`guardrail_fragments`]).
pub fn guardrail_from_bytes(b: &[u8]) -> Option<(&str, &str)> {
    if b.len() < 4 || le_u32(b, 0) != GUARDRAIL {
        return None;
    }
    let body = core::str::from_utf8(b.get(4..)?).ok()?;
    body.split_once('\0')
}

/// The non-empty fragments of one tier.
pub fn guardrail_fragments(tier: &str) -> impl Iterator<Item = &str> {
    tier.split('\n').filter(|fragment| !fragment.is_empty())
}

/// Builds a MIRAGE message (code + patterns + NUL + decoy suffix).
#[cfg(feature = "client")]
pub fn mirage_to_bytes(patterns: &[&str], suffix: &str) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&MIRAGE.to_le_bytes());
    v.extend_from_slice(patterns.join("\n").as_bytes());
    v.push(0);
    v.extend_from_slice(suffix.as_bytes());
    v
}

/// Parses a MIRAGE message; `None` if the code is wrong, the body is not UTF-8, or the patterns and
/// the suffix are not NUL-separated.
pub fn mirage_from_bytes(b: &[u8]) -> Option<(&str, &str)> {
    if b.len() < 4 || le_u32(b, 0) != MIRAGE {
        return None;
    }
    let body = core::str::from_utf8(b.get(4..)?).ok()?;
    body.split_once('\0')
}

/// The non-empty fragments of the Mirage pattern list.
pub fn mirage_fragments(patterns: &str) -> impl Iterator<Item = &str> {
    patterns.split('\n').filter(|fragment| !fragment.is_empty())
}

fn le_u32(b: &[u8], i: usize) -> u32 {
    u32::from_le_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]])
}

fn le_u64(b: &[u8], i: usize) -> u64 {
    (le_u32(b, i) as u64) | ((le_u32(b, i + 4) as u64) << 32)
}

pub fn adopt_to_bytes(child: ProcessKey, causal: ProcessKey) -> [u8; ADOPT_SIZE] {
    let mut b = [0u8; ADOPT_SIZE];
    b[0..4].copy_from_slice(&ADOPT.to_le_bytes());
    b[4..8].copy_from_slice(&child.pid.to_le_bytes());
    b[8..16].copy_from_slice(&child.create_time.to_le_bytes());
    b[16..20].copy_from_slice(&causal.pid.to_le_bytes());
    b[20..28].copy_from_slice(&causal.create_time.to_le_bytes());
    b
}

pub fn adopt_from_bytes(b: &[u8]) -> Option<(ProcessKey, ProcessKey)> {
    if b.len() != ADOPT_SIZE || le_u32(b, 0) != ADOPT {
        return None;
    }
    Some((
        ProcessKey {
            pid: le_u32(b, 4),
            create_time: le_u64(b, 8),
        },
        ProcessKey {
            pid: le_u32(b, 16),
            create_time: le_u64(b, 20),
        },
    ))
}

// the parent session and `Persisted` from pids are 0 when there is none, as in ProcessCreateEvent
pub fn adopt_tag_to_bytes(child: ProcessKey, session: SessionTag) -> [u8; ADOPT_TAG_SIZE] {
    let parent = session.parent_session.unwrap_or(ProcessKey {
        pid: 0,
        create_time: 0,
    });
    let from = from_of(session.kind);
    let mut b = [0u8; ADOPT_TAG_SIZE];
    b[0..4].copy_from_slice(&ADOPT_TAG.to_le_bytes());
    b[4..8].copy_from_slice(&child.pid.to_le_bytes());
    b[8..16].copy_from_slice(&child.create_time.to_le_bytes());
    b[16..20].copy_from_slice(&kind_to_u32(session.kind).to_le_bytes());
    b[20..24].copy_from_slice(&session.root.pid.to_le_bytes());
    b[24..32].copy_from_slice(&session.root.create_time.to_le_bytes());
    b[32..36].copy_from_slice(&parent.pid.to_le_bytes());
    b[36..44].copy_from_slice(&parent.create_time.to_le_bytes());
    b[44..48].copy_from_slice(&from.pid.to_le_bytes());
    b[48..56].copy_from_slice(&from.create_time.to_le_bytes());
    b
}

pub fn adopt_tag_from_bytes(b: &[u8]) -> Option<(ProcessKey, SessionTag)> {
    if b.len() != ADOPT_TAG_SIZE || le_u32(b, 0) != ADOPT_TAG {
        return None;
    }
    let parent = ProcessKey {
        pid: le_u32(b, 32),
        create_time: le_u64(b, 36),
    };
    let from = ProcessKey {
        pid: le_u32(b, 44),
        create_time: le_u64(b, 48),
    };
    Some((
        ProcessKey {
            pid: le_u32(b, 4),
            create_time: le_u64(b, 8),
        },
        SessionTag {
            root: ProcessKey {
                pid: le_u32(b, 20),
                create_time: le_u64(b, 24),
            },
            kind: kind_from_u32(le_u32(b, 16), from)?,
            parent_session: (parent.pid != 0).then_some(parent),
        },
    ))
}

/// Builds a MOTA_ADD message: code + FileId (volume + 128-bit id) + session + path length + path.
#[cfg(feature = "client")]
pub fn mota_add_to_bytes(file_id: FileId, session: SessionTag, path: &str) -> Vec<u8> {
    let parent = session.parent_session.unwrap_or(ProcessKey {
        pid: 0,
        create_time: 0,
    });
    let from = from_of(session.kind);
    let mut v = Vec::new();
    v.extend_from_slice(&MOTA_ADD.to_le_bytes());
    v.extend_from_slice(&file_id.volume.to_le_bytes());
    v.extend_from_slice(&file_id.id);
    v.extend_from_slice(&kind_to_u32(session.kind).to_le_bytes());
    v.extend_from_slice(&session.root.pid.to_le_bytes());
    v.extend_from_slice(&session.root.create_time.to_le_bytes());
    v.extend_from_slice(&parent.pid.to_le_bytes());
    v.extend_from_slice(&parent.create_time.to_le_bytes());
    v.extend_from_slice(&from.pid.to_le_bytes());
    v.extend_from_slice(&from.create_time.to_le_bytes());
    v.extend_from_slice(&(path.len() as u32).to_le_bytes());
    v.extend_from_slice(path.as_bytes());
    v
}

/// Parses a MOTA_ADD message (driver side; does not need the `client` feature).
pub fn mota_add_from_bytes(b: &[u8]) -> Option<(FileId, SessionTag, &str)> {
    let header = 4 + 8 + 16 + SESSION_BLOB_SIZE as usize + 4;
    if b.len() < header || le_u32(b, 0) != MOTA_ADD {
        return None;
    }
    let volume = le_u64(b, 4);
    let id: [u8; 16] = b.get(12..28)?.try_into().ok()?;
    let from = ProcessKey {
        pid: le_u32(b, 56),
        create_time: le_u64(b, 60),
    };
    let parent = ProcessKey {
        pid: le_u32(b, 44),
        create_time: le_u64(b, 48),
    };
    let session = SessionTag {
        root: ProcessKey {
            pid: le_u32(b, 32),
            create_time: le_u64(b, 36),
        },
        kind: kind_from_u32(le_u32(b, 28), from)?,
        parent_session: (parent.pid != 0).then_some(parent),
    };
    let len = le_u32(b, 68) as usize;
    let path = core::str::from_utf8(b.get(72..72 + len)?).ok()?;
    Some((FileId { volume, id }, session, path))
}

#[cfg(test)]
mod tests {
    use ariadne::AgentKind;

    use super::*;

    #[cfg(feature = "client")]
    #[test]
    fn mota_add_round_trip() {
        let file_id = FileId {
            volume: 0x1122_3344_5566_7788,
            id: [9; 16],
        };
        let session = SessionTag {
            root: ProcessKey {
                pid: 6804,
                create_time: 134370606314320447,
            },
            kind: AgentKind::Persisted {
                from: ProcessKey {
                    pid: 7,
                    create_time: 8,
                },
            },
            parent_session: Some(ProcessKey {
                pid: 100,
                create_time: 9,
            }),
        };
        let path = r"\??\C:\shem\.git\hooks\pre-commit";
        let msg = mota_add_to_bytes(file_id, session, path);
        assert_eq!(mota_add_from_bytes(&msg), Some((file_id, session, path)));
        assert_eq!(mota_add_from_bytes(&msg[..msg.len() - 1]), None);
    }

    #[test]
    fn adopt_round_trip() {
        let child = ProcessKey {
            pid: 9044,
            create_time: 134370606448266601,
        };
        let causal = ProcessKey {
            pid: 6804,
            create_time: 134370606314320447,
        };
        assert_eq!(
            adopt_from_bytes(&adopt_to_bytes(child, causal)),
            Some((child, causal))
        );
        let mut other = adopt_to_bytes(child, causal);
        other[0] = 0;
        assert_eq!(adopt_from_bytes(&other), None);
    }

    #[test]
    fn adopt_tag_round_trip() {
        let child = ProcessKey {
            pid: 9044,
            create_time: 134370606448266601,
        };
        let root = ProcessKey {
            pid: 6804,
            create_time: 134370606314320447,
        };
        for parent_session in [
            None,
            Some(ProcessKey {
                pid: 100,
                create_time: 7,
            }),
        ] {
            for kind in [AgentKind::Codex, AgentKind::Persisted { from: root }] {
                let session = SessionTag {
                    root,
                    kind,
                    parent_session,
                };
                assert_eq!(
                    adopt_tag_from_bytes(&adopt_tag_to_bytes(child, session)),
                    Some((child, session))
                );
            }
        }
        assert_eq!(
            adopt_from_bytes(&adopt_tag_to_bytes(
                child,
                SessionTag {
                    root,
                    kind: AgentKind::Claude,
                    parent_session: None
                }
            )),
            None
        );
    }

    #[cfg(feature = "client")]
    #[test]
    fn guardrail_round_trip() {
        let msg = guardrail_to_bytes(
            &["\\.claude\\settings.json", "\\managed-settings.json"],
            &["\\any-process.json"],
        );
        let (tagged, any) = guardrail_from_bytes(&msg).unwrap();
        assert_eq!(
            guardrail_fragments(tagged).collect::<Vec<_>>(),
            ["\\.claude\\settings.json", "\\managed-settings.json"]
        );
        assert_eq!(
            guardrail_fragments(any).collect::<Vec<_>>(),
            ["\\any-process.json"]
        );

        let empty = guardrail_to_bytes(&[], &[]);
        let (tagged, any) = guardrail_from_bytes(&empty).unwrap();
        assert_eq!(guardrail_fragments(tagged).count(), 0);
        assert_eq!(guardrail_fragments(any).count(), 0);

        assert_eq!(guardrail_from_bytes(&[0, 0, 0, 0]), None);
    }

    #[cfg(feature = "client")]
    #[test]
    fn mirage_round_trip() {
        let msg = mirage_to_bytes(&[r"\.aws\credentials", r"\.env"], ".mirage");
        let (patterns, suffix) = mirage_from_bytes(&msg).unwrap();
        assert_eq!(
            mirage_fragments(patterns).collect::<Vec<_>>(),
            [r"\.aws\credentials", r"\.env"]
        );
        assert_eq!(suffix, ".mirage");

        let empty = mirage_to_bytes(&[], ".mirage");
        let (patterns, suffix) = mirage_from_bytes(&empty).unwrap();
        assert_eq!(mirage_fragments(patterns).count(), 0);
        assert_eq!(suffix, ".mirage");

        assert_eq!(mirage_from_bytes(&[0, 0, 0, 0]), None);
    }

    #[cfg(feature = "client")]
    #[test]
    fn mirage_except_round_trip() {
        let msg = mirage_except_to_bytes(&[r"\work\deploy"], &["6804:123", "900:456"]);
        let (paths, sessions) = mirage_except_from_bytes(&msg).unwrap();
        assert_eq!(
            mirage_fragments(paths).collect::<Vec<_>>(),
            [r"\work\deploy"]
        );
        assert_eq!(
            mirage_fragments(sessions).collect::<Vec<_>>(),
            ["6804:123", "900:456"]
        );

        let empty = mirage_except_to_bytes(&[], &[]);
        let (paths, sessions) = mirage_except_from_bytes(&empty).unwrap();
        assert_eq!(mirage_fragments(paths).count(), 0);
        assert_eq!(mirage_fragments(sessions).count(), 0);

        assert_eq!(mirage_except_from_bytes(&[0, 0, 0, 0]), None);
    }
}
