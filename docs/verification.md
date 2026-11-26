# Verification notes

What has actually been run, on what, and what is still open. This is a lab record, not a
guarantee.

## Environment

- Guest: Windows 11 Enterprise Evaluation, Hyper-V VM (`Shem-Lab`), 4 vCPU / 6 GB, test signing on,
  the test certificate trusted in `Root` and `TrustedPublisher`.
- Toolchain: the nightly pinned in `rust-toolchain.toml` (`nightly-2026-05-08`), driver built in
  release from `ramon-km/` (`build-std`, `no_global_oom_handling`), signed with `signtool` and the
  test certificate.
- Harness: `scripts/install.ps1` + `scripts/smoke.ps1` (install, run the client for a few seconds,
  count events, unload, fail on no events or a new bugcheck). `fltmc filters` and `netsh wfp show
  state` cross-check the driver state.

## What works

| Check | Result |
|---|---|
| `fltmc load` | filter attaches to 4 volumes at altitude 345102 |
| client events | 38-986 events in 2-5 s per run (image loads, process creates, registry writes; file traffic only for `.exe` and tagged writes) |
| `fltmc unload` | returns 0, the minifilter is unregistered (`fltmc filters` empty) |
| repeated install | works in the same boot: load → unload → load → unload (see below) |

Representative runs (all `SMOKE TEST PASSED`):

- 713 events in ~5 s, clean unload;
- 474 events, clean unload;
- 899 / 986 events after longer client runs;
- 191-320 events on short 2-4 s runs in later iterations.

## Bug found during this testing

**0xA (IRQL_NOT_LESS_OR_EQUAL) on the first `fltmc load`.** `start_sender` locked a `FAST_MUTEX`
that was never initialized (the static-mut refactor dropped the `G_MUTEX.Init()` call). A zeroed
`FAST_MUTEX` is "locked", so the acquire waited on a zeroed `KEVENT` (NULL wait list) and
bugchecked. Fixed by calling `init()` before the first lock; debug builds now assert it
(`Locked` has an `initialized` flag checked with `debug_assert!`).

## WFP teardown and unload (fixed 2026-11-25)

Three defects kept the image mapped or crashed the unload:

1. **Lock held across the teardown.** The WFP calls must run at PASSIVE_LEVEL, but `net::stop` held
   the state `FAST_MUTEX` (APC_LEVEL), so every call returned `STATUS_NOT_SUPPORTED` (`0xC00000BB`,
   measured by writing the statuses to the registry). The sublayer, callout objects and filters
   stayed in BFE and the callout registration kept the driver image mapped. Fix: copy what is needed
   under the lock, drop it, then call WFP.
2. **Flow contexts pinned the runtime callout.** `FwpsFlowAssociateContext0` stored a session/pid
   context per flow, but nothing ever read it - the event is built from a fresh tag lookup at
   `ALE_FLOW_ESTABLISHED`. While a flow was alive, `FwpsCalloutUnregisterById0` returned
   `STATUS_DEVICE_BUSY` (the documented remedy is `FwpsFlowRemoveContext0` per flow). The context
   was unused, so it was removed: no association, no `flowDeleteFn`, no pool.
3. **The registry callback outlived the image (bugcheck 0xCE).** A kernel dump showed
   `nt!CmpCallCallBacksEx` calling `<Unloaded_ramon.sys>` from `NtQueryValueKey`. `km-api-sys`
   declares the `CmRegisterCallbackEx` cookie as `&LARGE_INTEGER`, but it is an out parameter; the
   refactor copied it through a zero-initialized local, so LLVM assumed the callee could not write
   through the shared reference and compiled the store to `G_COOKIE` as zero.
   `CmUnRegisterCallback(0)` failed (its status was ignored), the callback stayed registered, and
   the next registry query dereferenced the freed image. Fixed with a local `*mut LARGE_INTEGER`
   declaration and a logged status. `ObUnRegisterCallbacks` no longer runs under the object state
   `FAST_MUTEX` (it requires PASSIVE_LEVEL), and `start_sender` clears
   `stop`/`delivering_since`/`dropped` so a reload keeps delivering events.

4. **Hardening after an independent review.** `S_MINIFILTER` is initialized before the sender
   thread and the notify callbacks start (otherwise the first `deliver` locks a zeroed
   `FAST_MUTEX` → 0xA); `PsCreateSystemThread` and `ObRegisterCallbacks` are no longer called while
   holding a `FAST_MUTEX` (they require PASSIVE, the guard is APC); a failed teardown is returned
   from `RamonUnload`, so FltMgr keeps the image loaded instead of letting a live callout/callback
   point into freed memory; busy/in-use teardown statuses get a short PASSIVE retry, and an already
   deleted object (`*_NOT_FOUND`) counts as success. Also fixed: no `&mut` aliasing on the shared
   WFP wake event, the sender `spare` vector is freed outside the queue lock, and the process tree
   is dropped outside the spinlock.

Measured in one boot: load → client + triggers → unload → load → client + triggers → unload. Both
loads attach the filter, both unloads return 0 and leave `fltmc filters` empty, the client exits
with 1 on each unload, events arrive on both cycles (2084 / 1915 lines), the boot time is unchanged
and there are no minidumps. `lab/test-baseline` finishes with no FAIL (one earlier run had a flaky
`events queued while client suspended`, retried with `lost=0`) and `lab/test-wfp.ps1` is 12/12.
The teardown logs every status; `netsh wfp show state` shows 0 sublayer / 0 callout / 0 filter after
the unload and `ramon.sys` is writable (image released). The boot marker in `install.ps1` was removed:
a second load in the same boot is now expected to work.

## Minifilter hardening (2026-11-25)

- **Communication port.** Only an elevated process (administrator/SYSTEM token) whose image name starts
  with `ramon-client` may connect; only one client at a time. `client_port` is atomic, and
  `on_disconnect` clears the MOTA-exempt client pid as well as the port. Beyond that, the connect
  context must carry `nonce || HMAC-SHA256(key, nonce)` (`common/src/handshake.rs`), verified in
  `on_connect` (constant-time MAC compare, a replayed nonce is refused). The name/elevation check
  stays as defense in depth. The 32-byte key is injected at build time from `RAMON_PORT_KEY` or a
  gitignored `.portkey` (`common/build.rs` -> `$OUT_DIR/port_key.rs`), so it never enters the source
  tree.
- **Guardrail bypasses.** The pre-set-information callback now checks the rename/link *destination*
  (`FltGetDestinationFileNameInformation`), the hardlink *source* (`FileLinkInformation*`),
  `FileShortNameInformation`, and the `*BypassAccessCheck` rename/link classes. The alert names the
  path that matched the rule.
- **Create coverage.** `FileCreateEvent` still reports every `.exe` open; other payload extensions
  (`.dll`, `.ps1`, `.bat`, `.js`, `.lnk`, archives, ...) are reported on write/delete intent, not on
  reads, so image loads do not flood the log. Kernel-mode creates no longer request a post-op.

A failed unload is retryable: each successfully removed notify callback is recorded, so a second
`fltmc unload` resumes instead of failing on an already-removed routine; the WFP teardown clears
each object's flag after its successful delete. A mandatory unload (`FLTFL_FILTER_UNLOAD_MANDATORY`)
runs the whole teardown best-effort rather than returning early, because FltMgr detaches anyway.

Measured with a tagged agent: a hardlink to `managed-settings.json` was refused (the link was not
created), rename-over and an ADS write were refused, the direct write kept the file, and `drop.ps1`
arrived as `FileCreateEvent`. The client still connects and the unload is clean; the full
`test-baseline` finishes with no FAIL and there are no minidumps. The only failure seen in an
earlier run was the known flaky `suspended client does not slow process creation` (11 s vs the 5 s
threshold), not repeated in the final run.

The communication-port handshake was verified on a fresh checkpoint: three forged connects from a
process named `ramon-client` (all-zero 64-byte proof, size 0, size 32) were refused with
`0x80070005`, the real client connected, and the unload stayed clean (no bugcheck, no minidumps);
the full `test-baseline` finished with no FAIL.

`RamonPreCreate` hands the name it already resolved to `RamonPostCreate` through the pre-op
completion context, so a tagged create resolves the name once (no per-file-object state; an earlier
persistent stream-handle cache was dropped because its contexts lived as long as the file object and
grew the pool after a burst of creates). `RamonInstanceSetup` refuses network and CD-ROM volumes
(`STATUS_FLT_DO_NOT_ATTACH`) and keeps an `FLT_INSTANCE_CONTEXT` with the volume device type; files
on network shares and CD-ROM media are therefore not monitored. The lab filter instance count dropped
from 4 to 3. Driver Verifier `/standard` (flags `0x001209bb`) over a full load/client/unload cycle:
8/8 checks, no bugcheck, no minidumps, no verifier violations.

## Driver Verifier

`verifier /standard /driver C:\Windows\System32\drivers\ramon.sys` (special pool, force IRQL
checking, pool tracking, I/O verification, deadlock detection, security checks, DDI compliance;
file-system-filter rules included), then one full cycle - install, client for 3 s, unload:

- 366 events decoded, `SMOKE TEST PASSED`;
- 0 bugchecks, no Driver Verifier events in the System log;
- `fltmc filters` empty after the unload.

The verifier was reset afterwards. A separate load/unload cycle with the verifier active also
returned from `fltmc unload` with 0 and unregistered the filter.

## Not done yet

- A long automated load/unload loop (the single reload cycle above is covered).
- Fuzzing of `common`'s deserializer (the host tests cover truncated/garbage input only).
- Any test on real hardware or a non-VM machine.
