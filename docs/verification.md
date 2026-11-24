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
| repeated install | works again after a reboot (see the open issue below) |

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

## Open issue: WFP teardown

`net::stop` calls the WFP teardown APIs while holding the state `FAST_MUTEX` (APC_LEVEL); the WFP
kernel APIs require PASSIVE_LEVEL, so every call returns `STATUS_NOT_SUPPORTED` (measured by
writing the statuses to the registry: `0xC00000BB` for all of them). The sublayer, callout objects
and filters stay in BFE, and the callout registration keeps the driver image mapped, so
`\Windows\System32\drivers\ramon.sys` cannot be replaced until a reboot.

A variant that copies what it needs under the lock and calls WFP after releasing it **does** work:
`netsh wfp show state` is clean afterwards (0 sublayer / 0 callout / 0 filter) and the image is
released. But in the lab that variant hung the guest during unload (twice, with and without a
connected client), so it was reverted. The next step is to find that hang (unload ordering? BFE
waiting on an in-flight classify?) before landing the fix.

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

- A long load/unload loop - blocked by the WFP issue above (each cycle needs a reboot).
- Fuzzing of `common`'s deserializer (the host tests cover truncated/garbage input only).
- Any test on real hardware or a non-VM machine.
