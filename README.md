# RAMON

A Windows kernel sensor written in Rust: a minifilter plus process, image-load, registry, handle-open
and WFP callouts, streaming structured events to a user-mode client over a minifilter communication
port.

It started as the kernel half of a sensor that attributes process activity to an *agent session* (an
AI coding assistant and every process it spawns) and grew into a set of kernel techniques that are
useful on their own. It is a **research prototype, not a product**: no policy engine, no UI, no
signing, no tests on the host. Read the [Limits](#limits-not-production) section before running it.

```
                       KERNEL (ramon.sys)
  process create ──▶ process tree + session tags (ariadne)  ─┐
  image load, registry, handle open ────────────────────────┐ │
  minifilter: create/write/set-info/section ────────────────┼─┤
    ├─ file telemetry (content extensions)                  │ │
    ├─ MOTA: mark files written by a tag, alert on reopen    │ │
    ├─ Mirage: swap the name for a decoy on read            │ │
    ├─ guardrail: deny writes/deletes to protected paths     │ │
    └─ section sync: catch memory-mapped writes              │ │
  WFP: egress flow per tag ─────────────────────────────────┘ │
                                                              ▼
                                          send_message: queue (32768)
                                          one sender thread ──▶ FltSendMessage
                                                                     │
                       USER MODE                        communication port "ramon"
                       ramon-client: FilterGetMessage ───────────────┘
```

## Crates

| Crate | What it is |
|---|---|
| `ramon-km` | the driver (`cdylib`, `no_std`); everything below |
| `common` | event structs, the port command format, serialization; builds for the driver (`default-features = false`) and for the host |
| `ariadne` | process lineage tree (`no_std`) with host tests: process keys `(pid, create_time)`, tags, adoption of orphans, descendant propagation |
| `ramon-client` | small viewer: connects to the port and prints events |

## Techniques worth reading

- `ramon-km/src/section_sync.rs` — memory-mapped writes never reach the write path with a process
  tag: the flush is paging I/O from a system thread at DISPATCH_LEVEL. The section lifecycle is
  watched instead; a write is flagged with one atomic bit at DISPATCH and reported from the next
  PASSIVE_LEVEL callback, with a final report on section release.
- `ramon-km/src/net.rs` — a WFP callout on `ALE_FLOW_ESTABLISHED` that reports one event per flow
  (5-tuple, for UDP the first datagram) only for tagged processes. The classify does no allocation,
  no I/O and no blocking: the process tree lives in NonPaged pool under a spinlock and events go to a
  static ring drained by a PASSIVE_LEVEL thread.
- `ramon-km/src/np_alloc.rs` + `spinlock.rs` — a `core::alloc::Allocator` over `ExAllocatePool2`
  (NonPaged) and a minimal spinlock, so state read at DISPATCH_LEVEL never page-faults.
- `ramon-km/src/mota.rs` — Mark-of-the-Agent: files written by a tagged process get a stream context
  with the session tag and are remembered by `FileId` (survives closing the handle); a later open by a
  different process is reported. Bounded fixed ring, no allocation.
- `ramon-km/src/mirage.rs` — a decoy visible only to the tagged process: the file object name is
  replaced in pre-create (`IoReplaceFileObjectName` + `FltSetCallbackDataDirty`), so the read is
  served from a decoy file.
- `ramon-km/src/send_message.rs` — a queue between callbacks and a single sender system thread, so a
  slow client never runs inside a callback.

## IRQL contracts

| Entry point | IRQL | May allocate / block? |
|---|---|---|
| `DriverEntry`, `RamonUnload` | PASSIVE | yes (load/unload path only) |
| process-create, image-load, registry, handle-open notify | PASSIVE | yes; they only enqueue |
| minifilter post-create, pre-set-information | PASSIVE | yes; they only enqueue |
| minifilter write post-op, section acquire/release | <= DISPATCH | **no**: atomics only, report deferred |
| WFP classify | <= DISPATCH | **no**: tree lookup under spinlock, static ring |
| sender thread, WFP drain thread | PASSIVE | yes (`FltSendMessage`, allocations) |

`send_message::send_message` may be called from the callbacks above (IRQL <= APC_LEVEL); it may wait
on a kernel event for queue space, never inside a spinlock.

## Event protocol

Every message from the port is `EventHeader { event_class: u32, event_size: u32 }` (little-endian)
followed by the event body. Classes are ASCII tags, e.g. `0x20455243` = `"CRE "`:

| Class | Event | Source |
|---|---|---|
| `CRE ` | `FileCreateEvent` | minifilter post-create |
| `PRO ` | `ProcessCreateEvent` | process notify (parent, image, command line) |
| `DLL ` | `ImageLoadEvent` | image-load notify |
| `REG ` | `RegistrySetValueEvent` | registry notify |
| `SES ` | `SessionAssignedEvent` | lineage: a process got a tag after creation |
| `FSI ` | `FileSetInformationEvent` | set-information: delete / rename |
| `FTE ` | `FileTelemetryEvent` | write/read open by a tagged process |
| `GRB ` | `GuardrailBlockedEvent` | pre-op denied a write/delete/rename |
| `HKO ` | `HandleOpenEvent` | handle open of another process by a tagged process |
| `CNY ` | `CanaryEvent` | a tagged process touched a decoy |
| `MOTA` | `MotaEvent` | marked file opened by a different process |
| `MIRG` | `MirageRedirectEvent` | read redirected to a decoy |
| `NFLW` | `NetFlowEvent` | WFP flow with a tag |

Commands travel the other way (client → driver) as a tagged byte buffer: `ADOPT_TAG`, `GUARDRAIL`,
`MIRAGE`, `MIRAGE_EXCEPT`. See `common/src/command.rs`.

## Build

Requirements: Windows, Visual Studio Build Tools, WDK 10, Rust nightly.

```
cd ramon-km
cargo build
```

Output: `target\x86_64-pc-windows-msvc\debug\ramon.dll` (rename to `ramon.sys`; `Makefile.toml` has
cargo-make tasks for rename/sign/inf2cat). The host crates build with the default toolchain:

```
cargo test -p ariadne -p common
cargo build -p ramon-client
```

The driver is built with `-Z build-std=core,alloc` and `--cfg no_global_oom_handling` (both in
`ramon-km/.cargo/config.toml`), so an infallible allocation cannot compile: every `Vec`/`String`
growth on a kernel path is fallible. `build-std` makes `compiler-builtins` reference the C
`fma`/`fmaf`, which a `/NODEFAULTLIB` driver does not link; `ramon-km/src/libm_shim.rs` provides
non-fused definitions only to satisfy the linker (the driver performs no floating-point math).

Load only on a test machine with test signing enabled:

```
fltmc load ramon
ramon-client.exe all
fltmc unload ramon
```

## Limits (not production)

This is an example. What that means concretely:

1. **Global state.** All module state lives in `static mut` behind one global `FAST_MUTEX`. That is
   one driver instance, no per-volume or per-client isolation, and no cleanup ordering beyond the
   unload callback. A production driver would hang the same state off the filter/instance contexts
   (`FltAllocateContext`) or the device object.
2. **A stuck client costs up to 10 s.** When the 32768-entry queue is full, callbacks wait for
   space; if one event has been waiting longer than `STALL` (10 s), the event is dropped and counted
   (`G_DROPPED`). A production sensor would drop at once or disconnect the client. A *disconnected*
   client never blocks anything: events are dropped immediately.
3. **Fixed capacities.** Everything is bounded and allocation-free on hot paths:
   32768 queued events, 64 writable-section slots (one `u64` pending bitmap), 4096 remembered
   `FileId`s, 4096-entry WFP ring, 256 flow-context slots, 64 descendant events per adoption,
   4 KiB command buffer, 512-byte log lines. Lookups over the rings are linear in the capacity.
4. **No host tests for the driver.** A kernel driver cannot be unit-tested on the host, and the lab
   harnesses (Hyper-V, Driver Verifier, load/unload cycles, end-to-end event checks) are not part of
   this repository. `ariadne` and `common` have real host tests (48 in total). Treat the driver as
   lab-verified only.
5. **Hand-declared ABI.** Symbols missing from `km-api-sys` are declared locally against the WDK
   headers; there is no build-time check that a prototype still matches. See
   [docs/abi.md](docs/abi.md).
6. **Scope.** x64 only. No policy, no blocking except guardrail denies and Mirage redirection (both
   opt-in over the port), no persistence of state across reboot, no self-protection (the driver is
   not PPL/ELAM), no signature.
7. **Mirage and MOTA are detection aids, not boundaries.** Mirage hides a decoy from one process
   tree by rewriting the create path; a determined caller can reach the file by other means. MOTA
   keys on `FileId`, so it sees reopens but not a copy made through an untagged process first.

If you need a production-grade component here, treat this as the reference implementation of the
callbacks and the protocol, not as the component.

## Provenance

Started as the `ramon-rs` example, built on [`windows-kernel-rs`](https://github.com/radkum/windows-kernel-rs)
(a public example of a Rust driver and minifilter) and on a fork of
[`winapi-rs`](https://github.com/Trantect/winapi-rs), branch `feature/km`. Lineage trees use
[`kernel-btree`](https://github.com/radkum/kernel-btree).

## License

Dual-licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option. Unless you explicitly state otherwise, any contribution intentionally submitted for
inclusion in this project by you shall be dual-licensed as above, without additional terms.
