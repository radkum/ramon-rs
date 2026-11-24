//! Process lineage of AI agents: tree tagging, propagation, causal parent. no_std, shared by driver and client.
#![no_std]

extern crate alloc;

use alloc::vec::Vec;

use kernel_btree::{BTreeMap, Global, RawAlloc};

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct ProcessKey {
    pub pid: u32,
    pub create_time: u64,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum AgentKind {
    Claude,
    Cursor,
    Codex,
    Opencode,
    Gemini,
    Grok,
    // a scheduled task started after its registering session ended (e.g. after a restart): `from` is that session
    Persisted { from: ProcessKey },
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct SessionTag {
    pub root: ProcessKey,
    pub kind: AgentKind,
    pub parent_session: Option<ProcessKey>,
}

pub fn agent_kind(image: &str) -> Option<AgentKind> {
    let name = image.rsplit(['\\', '/']).next().unwrap_or(image);
    [
        ("claude.exe", AgentKind::Claude),
        ("cursor.exe", AgentKind::Cursor),
        ("codex.exe", AgentKind::Codex),
        ("opencode.exe", AgentKind::Opencode),
        ("gemini.exe", AgentKind::Gemini),
        ("grok.exe", AgentKind::Grok),
    ]
    .into_iter()
    .find(|(root, _)| name.eq_ignore_ascii_case(root))
    .map(|(_, kind)| kind)
}

/// A Node-based CLI agent runs as the generic `node.exe`, so the image name does not identify it; the
/// entry script in the command line does (Cursor: `...\cursor-agent\index.js`, Gemini:
/// `...\@google\gemini-cli\bundle\gemini.js`). Restricted to `node.exe`, and each marker carries a path
/// separator, so an unrelated `node` script that merely mentions the name (a user's own `gemini.js`, a
/// grep argument) does not become a session root.
fn node_agent_kind(image: &str, command_line: &str) -> Option<AgentKind> {
    let name = image.rsplit(['\\', '/']).next().unwrap_or(image);
    if !name.eq_ignore_ascii_case("node.exe") {
        return None;
    }
    [
        (r"\cursor-agent\", AgentKind::Cursor),
        ("/cursor-agent/", AgentKind::Cursor),
        (r"\gemini-cli\", AgentKind::Gemini),
        ("/gemini-cli/", AgentKind::Gemini),
        (r"\gemini.js", AgentKind::Gemini),
        ("/gemini.js", AgentKind::Gemini),
    ]
    .into_iter()
    .find(|(marker, _)| contains_ignore_ascii_case(command_line, marker))
    .map(|(_, kind)| kind)
}

fn contains_ignore_ascii_case(haystack: &str, needle: &str) -> bool {
    let (haystack, needle) = (haystack.as_bytes(), needle.as_bytes());
    !needle.is_empty()
        && needle.len() <= haystack.len()
        && haystack.windows(needle.len()).any(|window| window.eq_ignore_ascii_case(needle))
}

/// Fallible `Vec::push`: works under `no_global_oom_handling` (the driver) and on stable (host tests),
/// where `Vec::push_within_capacity` is still unstable. Returns false when the reservation fails.
fn try_push<T: Copy>(v: &mut Vec<T>, value: T) -> bool {
    if v.try_reserve(1).is_err() {
        return false;
    }
    let len = v.len();
    v.spare_capacity_mut()[0].write(value);
    unsafe { v.set_len(len + 1) };
    true
}

/// Allocation failed in `on_create`; `tag` is what the process would have got, so the caller can deny it.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct OutOfMemory {
    pub tag: Option<SessionTag>,
}

#[derive(Debug, Copy, Clone)]
struct Node {
    create_time: u64,
    tag: Option<SessionTag>,
    // zero create time when the parent was not live: it cannot be matched later
    parent: ProcessKey,
}

const RECENT_EXITS: usize = 64;

/// Live processes only: a parent is alive while its child is being created, so dead nodes are not needed.
/// Keyed by pid; only fallible allocation (the driver builds alloc with no_global_oom_handling).
pub struct ProcessTree<A: RawAlloc = Global> {
    live: BTreeMap<u32, Node, A>,
    // tagged processes that exited, for `adopt`: a WMI client often exits before ETW reports its child
    exited: [Option<(ProcessKey, SessionTag)>; RECENT_EXITS],
    next_exited: usize,
}

impl Default for ProcessTree {
    fn default() -> Self {
        Self::new()
    }
}

impl ProcessTree {
    pub const fn new() -> Self {
        Self::new_in(Global)
    }
}

impl<A: RawAlloc> ProcessTree<A> {
    pub const fn new_in(alloc: A) -> Self {
        Self { live: BTreeMap::new_in(alloc), exited: [None; RECENT_EXITS], next_exited: 0 }
    }

    /// `creator_pid` is the process owning `CreatingThreadId`; it differs from `parent_pid` under PPID spoofing.
    /// `command_line` catches Node-based CLI agents, whose image is the generic `node.exe`.
    pub fn on_create(
        &mut self,
        key: ProcessKey,
        parent_pid: u32,
        creator_pid: u32,
        image: &str,
        command_line: &str,
    ) -> Result<Option<SessionTag>, OutOfMemory> {
        let inherited = self.tag_of(creator_pid).or(self.tag_of(parent_pid));
        let kind = agent_kind(image).or_else(|| node_agent_kind(image, command_line));
        let tag = match kind {
            Some(kind) => {
                Some(SessionTag { root: key, kind, parent_session: inherited.map(|t| t.root) })
            },
            None => inherited,
        };
        let parent_create_time = self.live.get(&parent_pid).map_or(0, |node| node.create_time);
        let parent = ProcessKey { pid: parent_pid, create_time: parent_create_time };
        let node = Node { create_time: key.create_time, tag, parent };
        self.live.try_insert(key.pid, node).map_err(|_| OutOfMemory { tag })?;
        Ok(tag)
    }

    pub fn on_exit(&mut self, key: ProcessKey) {
        if self.live.get(&key.pid).is_some_and(|node| node.create_time == key.create_time) {
            if let Some(tag) = self.live.remove(&key.pid).and_then(|node| node.tag) {
                self.exited[self.next_exited] = Some((key, tag));
                self.next_exited = (self.next_exited + 1) % RECENT_EXITS;
            }
        }
    }

    pub fn tag_of(&self, pid: u32) -> Option<SessionTag> {
        self.live.get(&pid).and_then(|node| node.tag)
    }

    /// `child` was started on behalf of `causal` (e.g. through WMI): an untagged live child gets causal's tag.
    /// `assigned` is called for every process tagged by it: the child and its descendants.
    pub fn adopt(
        &mut self,
        child: ProcessKey,
        causal: ProcessKey,
        assigned: impl FnMut(ProcessKey, SessionTag),
    ) -> Option<SessionTag> {
        let tag = match self.live.get(&causal.pid) {
            Some(node) if node.create_time == causal.create_time => node.tag,
            _ => self.exited.iter().flatten().find(|(key, _)| *key == causal).map(|(_, tag)| *tag),
        }?;
        self.adopt_tag(child, tag, assigned)
    }

    /// Gives an untagged live child `tag` directly, for a causal process that may already be gone.
    pub fn adopt_tag(
        &mut self,
        child: ProcessKey,
        tag: SessionTag,
        mut assigned: impl FnMut(ProcessKey, SessionTag),
    ) -> Option<SessionTag> {
        let node = self.live.get_mut(&child.pid)?;
        if node.create_time != child.create_time || node.tag.is_some() {
            return None;
        }
        node.tag = Some(tag);
        assigned(child, tag);
        self.tag_descendants(child, tag, &mut assigned);
        Some(tag)
    }

    // children started before the adoption have no tag yet: tag them level by level. The frontier is a
    // fallible Vec (the driver builds alloc with no_global_oom_handling), so a wide level is not capped.
    fn tag_descendants(
        &mut self,
        root: ProcessKey,
        tag: SessionTag,
        assigned: &mut impl FnMut(ProcessKey, SessionTag),
    ) {
        let mut level: Vec<ProcessKey> = Vec::new();
        if !try_push(&mut level, root) {
            return;
        }
        while !level.is_empty() {
            let mut next: Vec<ProcessKey> = Vec::new();
            for (&pid, node) in self.live.iter() {
                if node.tag.is_none()
                    && level.contains(&node.parent)
                    && !try_push(&mut next, ProcessKey { pid, create_time: node.create_time })
                {
                    break;
                }
            }
            for key in &next {
                if let Some(node) = self.live.get_mut(&key.pid) {
                    node.tag = Some(tag);
                    assigned(*key, tag);
                }
            }
            level = next;
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use core::{alloc::Layout, cell::Cell};
    use std::{
        alloc::{GlobalAlloc, System},
        vec::Vec,
    };

    use super::*;

    const EXPLORER: ProcessKey = ProcessKey { pid: 100, create_time: 1 };

    fn key(pid: u32, create_time: u64) -> ProcessKey {
        ProcessKey { pid, create_time }
    }

    fn tree_with_explorer() -> ProcessTree {
        let mut tree = ProcessTree::new();
        tree.on_create(EXPLORER, 4, 4, r"C:\Windows\explorer.exe", "").unwrap();
        tree
    }

    #[test]
    fn root_starts_new_session() {
        let mut tree = tree_with_explorer();
        let claude = key(200, 10);
        let tag = tree
            .on_create(claude, EXPLORER.pid, EXPLORER.pid, r"C:\Users\a\.local\bin\claude.exe", "")
            .unwrap();
        assert_eq!(
            tag,
            Some(SessionTag { root: claude, kind: AgentKind::Claude, parent_session: None })
        );
        assert_eq!(tree.tag_of(claude.pid), tag);
    }

    #[test]
    fn descendants_inherit_tag() {
        let mut tree = tree_with_explorer();
        let root =
            tree.on_create(key(200, 10), EXPLORER.pid, EXPLORER.pid, "cursor.exe", "").unwrap();
        tree.on_create(key(300, 11), 200, 200, r"C:\Windows\System32\cmd.exe", "").unwrap();
        let grandchild = tree
            .on_create(key(400, 12), 300, 300, r"C:\Program Files\nodejs\node.exe", "")
            .unwrap();
        assert_eq!(grandchild, root);
        assert_eq!(tree.tag_of(300), root);
    }

    #[test]
    fn processes_outside_tree_are_untagged() {
        let mut tree = tree_with_explorer();
        tree.on_create(key(200, 10), EXPLORER.pid, EXPLORER.pid, "codex.exe", "").unwrap();
        assert_eq!(
            tree.on_create(key(300, 11), EXPLORER.pid, EXPLORER.pid, "notepad.exe", "").unwrap(),
            None
        );
        assert_eq!(tree.tag_of(EXPLORER.pid), None);
        assert_eq!(tree.tag_of(999), None);
    }

    #[test]
    fn reused_pid_does_not_inherit_old_tag() {
        let mut tree = tree_with_explorer();
        tree.on_create(key(200, 10), EXPLORER.pid, EXPLORER.pid, "claude.exe", "").unwrap();
        tree.on_create(key(300, 11), 200, 200, "cmd.exe", "").unwrap();
        tree.on_exit(key(300, 11));
        assert_eq!(
            tree.on_create(key(300, 50), EXPLORER.pid, EXPLORER.pid, "cmd.exe", "").unwrap(),
            None
        );
        assert_eq!(tree.tag_of(300), None);
    }

    #[test]
    fn stale_exit_keeps_live_process() {
        let mut tree = tree_with_explorer();
        let tag =
            tree.on_create(key(200, 10), EXPLORER.pid, EXPLORER.pid, "claude.exe", "").unwrap();
        tree.on_exit(key(200, 9));
        assert_eq!(tree.tag_of(200), tag);
    }

    #[test]
    fn orphan_keeps_tag_after_root_exit() {
        let mut tree = tree_with_explorer();
        let root =
            tree.on_create(key(200, 10), EXPLORER.pid, EXPLORER.pid, "claude.exe", "").unwrap();
        tree.on_create(key(300, 11), 200, 200, "node.exe", "").unwrap();
        tree.on_exit(key(200, 10));
        assert_eq!(tree.tag_of(200), None);
        assert_eq!(tree.tag_of(300), root);
        assert_eq!(tree.on_create(key(400, 12), 300, 300, "git.exe", "").unwrap(), root);
    }

    #[test]
    fn spoofed_parent_falls_back_to_creator() {
        let mut tree = tree_with_explorer();
        let root =
            tree.on_create(key(200, 10), EXPLORER.pid, EXPLORER.pid, "claude.exe", "").unwrap();
        assert_eq!(
            tree.on_create(key(300, 11), EXPLORER.pid, 200, "powershell.exe", "").unwrap(),
            root
        );
    }

    #[test]
    fn nested_agent_starts_child_session() {
        let mut tree = tree_with_explorer();
        let cursor = key(200, 10);
        tree.on_create(cursor, EXPLORER.pid, EXPLORER.pid, "Cursor.exe", "").unwrap();
        tree.on_create(key(300, 11), 200, 200, "pwsh.exe", "").unwrap();
        let claude = key(400, 12);
        let tag = tree.on_create(claude, 300, 300, "claude.exe", "").unwrap();
        assert_eq!(
            tag,
            Some(SessionTag {
                root: claude,
                kind: AgentKind::Claude,
                parent_session: Some(cursor)
            })
        );
        assert_eq!(tree.on_create(key(500, 13), 400, 400, "cmd.exe", "").unwrap(), tag);
    }

    #[test]
    fn lookup_survives_out_of_order_pids() {
        let mut tree = tree_with_explorer();
        let root =
            tree.on_create(key(900, 10), EXPLORER.pid, EXPLORER.pid, "claude.exe", "").unwrap();
        tree.on_create(key(50, 11), 900, 900, "cmd.exe", "").unwrap();
        tree.on_create(key(500, 12), EXPLORER.pid, EXPLORER.pid, "notepad.exe", "").unwrap();
        tree.on_create(key(7, 13), 50, 50, "node.exe", "").unwrap();
        assert_eq!([tree.tag_of(7), tree.tag_of(50), tree.tag_of(900)], [root; 3]);
        assert_eq!([tree.tag_of(100), tree.tag_of(500)], [None; 2]);
        tree.on_exit(key(50, 11));
        assert_eq!([tree.tag_of(7), tree.tag_of(50), tree.tag_of(900)], [root, None, root]);
    }

    #[test]
    fn adopted_child_gets_causal_tag_and_passes_it_on() {
        let mut tree = tree_with_explorer();
        let root =
            tree.on_create(key(200, 10), EXPLORER.pid, EXPLORER.pid, "claude.exe", "").unwrap();
        tree.on_create(key(300, 11), 200, 200, "powershell.exe", "").unwrap();
        let wmi_child = key(500, 13);
        tree.on_create(wmi_child, 400, 400, "ping.exe", "").unwrap();
        let mut assigned = Vec::new();
        assert_eq!(tree.adopt(wmi_child, key(300, 11), |k, t| assigned.push((k, t))), root);
        assert_eq!(assigned, [(wmi_child, root.unwrap())]);
        assert_eq!(tree.tag_of(500), root);
        assert_eq!(tree.on_create(key(600, 14), 500, 500, "cmd.exe", "").unwrap(), root);
    }

    #[test]
    fn adopt_after_causal_exit() {
        let mut tree = tree_with_explorer();
        let root =
            tree.on_create(key(200, 10), EXPLORER.pid, EXPLORER.pid, "claude.exe", "").unwrap();
        tree.on_create(key(300, 11), 200, 200, "powershell.exe", "").unwrap();
        tree.on_create(key(500, 13), 400, 400, "ping.exe", "").unwrap();
        tree.on_exit(key(300, 11));
        tree.on_create(key(300, 20), EXPLORER.pid, EXPLORER.pid, "notepad.exe", "").unwrap();
        assert_eq!(tree.adopt(key(500, 13), key(300, 11), |_, _| ()), root);
    }

    #[test]
    fn adopt_tag_gives_tag_without_live_causal() {
        let mut tree = tree_with_explorer();
        let root = tree
            .on_create(key(200, 10), EXPLORER.pid, EXPLORER.pid, "claude.exe", "")
            .unwrap()
            .unwrap();
        tree.on_create(key(500, 13), 400, 400, "ping.exe", "").unwrap();
        assert_eq!(tree.adopt_tag(key(500, 12), root, |_, _| ()), None);
        assert_eq!(tree.adopt_tag(key(500, 13), root, |_, _| ()), Some(root));
        assert_eq!(tree.tag_of(500), Some(root));
        let mut assigned = 0;
        assert_eq!(tree.adopt_tag(key(500, 13), root, |_, _| assigned += 1), None);
        assert_eq!(assigned, 0);
    }

    #[test]
    fn adopt_tag_tags_descendants_started_before_it() {
        let mut tree = tree_with_explorer();
        let root = tree
            .on_create(key(200, 10), EXPLORER.pid, EXPLORER.pid, "claude.exe", "")
            .unwrap()
            .unwrap();
        tree.on_create(key(500, 13), 400, 400, "ping.exe", "").unwrap();
        tree.on_create(key(600, 14), 500, 500, "conhost.exe", "").unwrap();
        tree.on_create(key(700, 15), 600, 600, "ping.exe", "").unwrap();
        tree.on_create(key(800, 16), 400, 400, "cmd.exe", "").unwrap();
        let mut assigned = Vec::new();
        tree.adopt_tag(key(500, 13), root, |k, _| assigned.push(k));
        assert_eq!(tree.tag_of(600), Some(root));
        assert_eq!(tree.tag_of(700), Some(root));
        assert_eq!(tree.tag_of(800), None);
        assert_eq!(assigned, [key(500, 13), key(600, 14), key(700, 15)]);
    }

    #[test]
    fn adopt_tag_reports_every_descendant() {
        let mut tree = tree_with_explorer();
        let root = tree
            .on_create(key(200, 10), EXPLORER.pid, EXPLORER.pid, "claude.exe", "")
            .unwrap()
            .unwrap();
        tree.on_create(key(500, 13), 400, 400, "cmd.exe", "").unwrap();
        for i in 0..40 {
            tree.on_create(key(1000 + i, 14), 500, 500, "cmd.exe", "").unwrap();
            tree.on_create(key(2000 + i, 15), 1000 + i, 1000 + i, "ping.exe", "").unwrap();
        }
        let mut assigned = Vec::new();
        tree.adopt_tag(key(500, 13), root, |k, _| assigned.push(k));
        // no per-level cap: the 40 children and their 40 grandchildren are all tagged
        assert_eq!(assigned.len(), 1 + 40 + 40);
        assert!(assigned.iter().all(|k| tree.tag_of(k.pid) == Some(root)));
    }

    #[test]
    fn adopt_tag_skips_children_of_a_reused_parent_pid() {
        let mut tree = tree_with_explorer();
        let root = tree
            .on_create(key(200, 10), EXPLORER.pid, EXPLORER.pid, "claude.exe", "")
            .unwrap()
            .unwrap();
        tree.on_create(key(500, 13), 400, 400, "ping.exe", "").unwrap();
        tree.on_create(key(600, 14), 500, 500, "conhost.exe", "").unwrap();
        tree.on_exit(key(500, 13));
        tree.on_create(key(500, 20), 400, 400, "ping.exe", "").unwrap();
        let mut assigned = Vec::new();
        tree.adopt_tag(key(500, 20), root, |k, _| assigned.push(k));
        assert_eq!(tree.tag_of(600), None);
        assert_eq!(assigned, [key(500, 20)]);
    }

    #[test]
    fn adopt_ignores_stale_keys_and_tagged_children() {
        let mut tree = tree_with_explorer();
        tree.on_create(key(200, 10), EXPLORER.pid, EXPLORER.pid, "claude.exe", "").unwrap();
        let cursor =
            tree.on_create(key(300, 11), EXPLORER.pid, EXPLORER.pid, "cursor.exe", "").unwrap();
        tree.on_create(key(500, 13), 400, 400, "ping.exe", "").unwrap();
        let mut assigned = 0;
        assert_eq!(tree.adopt(key(500, 12), key(200, 10), |_, _| assigned += 1), None);
        assert_eq!(tree.adopt(key(500, 13), key(200, 9), |_, _| assigned += 1), None);
        assert_eq!(tree.adopt(key(500, 13), key(100, 1), |_, _| assigned += 1), None);
        assert_eq!(tree.tag_of(500), None);
        assert_eq!(tree.adopt(key(300, 11), key(200, 10), |_, _| assigned += 1), None);
        assert_eq!(tree.tag_of(300), cursor);
        assert_eq!(assigned, 0);
    }

    #[test]
    fn agent_kind_matches_file_name_only() {
        assert_eq!(
            agent_kind(r"\Device\HarddiskVolume3\Tools\CLAUDE.EXE"),
            Some(AgentKind::Claude)
        );
        assert_eq!(agent_kind("/usr/bin/codex.exe"), Some(AgentKind::Codex));
        assert_eq!(
            agent_kind(r"C:\Users\a\AppData\Roaming\npm\opencode.exe"),
            Some(AgentKind::Opencode)
        );
        assert_eq!(agent_kind(r"C:\Users\a\.local\bin\gemini.exe"), Some(AgentKind::Gemini));
        assert_eq!(agent_kind(r"C:\Users\a\.local\bin\grok.exe"), Some(AgentKind::Grok));
        assert_eq!(agent_kind(r"C:\claude.exe\node.exe"), None);
        assert_eq!(agent_kind("notclaude.exe"), None);
        assert_eq!(agent_kind("claude.exe.bak"), None);
    }

    #[test]
    fn node_agent_kind_matches_entry_script_only_for_node() {
        // Cursor and Gemini CLI run as the generic node.exe; the entry script in the command line
        // identifies them
        let cursor = r#""C:\Users\a\AppData\Local\cursor-agent\versions\x\node.exe" "C:\Users\a\AppData\Local\cursor-agent\versions\x\index.js" -p --force hi"#;
        assert_eq!(node_agent_kind("node.exe", cursor), Some(AgentKind::Cursor));
        assert_eq!(
            node_agent_kind(r"C:\Program Files\nodejs\node.exe", cursor),
            Some(AgentKind::Cursor)
        );
        let gemini = r#""C:\Program Files\nodejs\node.exe" "C:\Users\a\AppData\Roaming\npm\node_modules\@google\gemini-cli\bundle\gemini.js" -p hi"#;
        assert_eq!(node_agent_kind("node.exe", gemini), Some(AgentKind::Gemini));
        // case-insensitive, and the bundle name alone is enough
        assert_eq!(
            node_agent_kind("NODE.EXE", r"node.exe C:\x\BUNDLE\GEMINI.JS -p hi"),
            Some(AgentKind::Gemini)
        );
        // a plain node script is not an agent, even one named like the entry scripts (no path separator)
        assert_eq!(node_agent_kind("node.exe", r"node.exe C:\x\app.js"), None);
        assert_eq!(node_agent_kind("node.exe", "node.exe gemini.js -p hi"), None);
        assert_eq!(node_agent_kind("node.exe", "node.exe cursor-agent.js"), None);
        // only node.exe: a shell running the shim, or any other image, is not a root
        assert_eq!(node_agent_kind("powershell.exe", cursor), None);
        assert_eq!(node_agent_kind("cmd.exe", cursor), None);
        assert_eq!(node_agent_kind("claude.exe", cursor), None);
    }

    #[test]
    fn node_agent_command_line_starts_session() {
        let mut tree = tree_with_explorer();
        let command_line = r#""C:\Users\a\AppData\Local\cursor-agent\versions\x\node.exe" "C:\Users\a\AppData\Local\cursor-agent\versions\x\index.js" -p --force hi"#;
        let node = key(200, 10);
        let tag = tree
            .on_create(
                node,
                EXPLORER.pid,
                EXPLORER.pid,
                r"C:\Program Files\nodejs\node.exe",
                command_line,
            )
            .unwrap();
        assert_eq!(
            tag,
            Some(SessionTag { root: node, kind: AgentKind::Cursor, parent_session: None })
        );
        assert_eq!(tree.tag_of(node.pid), tag);
    }

    /// Fails every allocation once `budget` runs out.
    struct Budget(Cell<usize>);

    unsafe impl RawAlloc for Budget {
        fn alloc(&self, layout: Layout) -> *mut u8 {
            if self.0.get() == 0 {
                return core::ptr::null_mut();
            }
            self.0.set(self.0.get() - 1);
            unsafe { System.alloc(layout) }
        }

        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            unsafe { System.dealloc(ptr, layout) }
        }
    }

    #[test]
    fn out_of_memory_reports_tag_and_keeps_tree() {
        let budget = Budget(Cell::new(usize::MAX));
        let mut tree = ProcessTree::new_in(&budget);
        let root =
            tree.on_create(key(200, 10), EXPLORER.pid, EXPLORER.pid, "claude.exe", "").unwrap();
        budget.0.set(0);
        // fill the node until an insert has to allocate
        let pid = (300..400)
            .find(|&pid| tree.on_create(key(pid, 11), 200, 200, "cmd.exe", "").is_err())
            .unwrap();
        assert_eq!(
            tree.on_create(key(pid, 11), 200, 200, "cmd.exe", ""),
            Err(OutOfMemory { tag: root })
        );
        assert_eq!(
            tree.on_create(key(pid, 11), EXPLORER.pid, EXPLORER.pid, "notepad.exe", ""),
            Err(OutOfMemory { tag: None })
        );
        assert_eq!(tree.tag_of(pid), None);
        assert_eq!(tree.tag_of(pid - 1), root);
        // pid reuse overwrites in place, no allocation
        assert_eq!(
            tree.on_create(key(200, 20), EXPLORER.pid, EXPLORER.pid, "cmd.exe", ""),
            Ok(None)
        );
        budget.0.set(usize::MAX);
        assert_eq!(tree.on_create(key(pid, 11), 300, 300, "cmd.exe", ""), Ok(root));
    }
}
