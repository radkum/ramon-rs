# RAMON

**Edition 2 of 2 - AI-assisted rewrite and extension (2026).** This edition was rebuilt and extended with an AI assistant. The original, hand-written 2025 minifilter is preserved at [adkum/ramon-rs-legacy](https://github.com/radkum/ramon-rs-legacy).

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
| `common` | event structs, the port command format, serialization and the port handshake; builds for the driver (`default-features = false`) and for the host |
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
- `ramon-km/src/locked.rs` — `Locked<T>`: static state without `static mut`. The data is reachable
  only through the guard returned by `lock()`, and the guard releases the `FAST_MUTEX` on drop, so
  no `&mut T` can be aliased and no module needs a `static_mut_refs` allowance.
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

The driver and the client share a 32-byte key for the communication-port handshake
(`common/src/handshake.rs`): the client proves it holds the key with `HMAC-SHA256` over a fresh
nonce in the connect context, and the driver verifies it. `common/build.rs` injects the key from
`RAMON_PORT_KEY` (64 hex chars) or a gitignored `.portkey` at the repo root, generating a random one
on the first build, so no secret is committed.

## Trying it

The driver is unsigned for release: load it only on a test machine. Enable test signing once
(`bcdedit /set testsigning on`, reboot), trust the signing certificate, then put `ramon.sys` and
`ramon-client.exe` next to the scripts:

```
ps> .\scripts\install.ps1        # service + instance altitude + fltmc load
ps> .\ramon-client.exe all       # prints events until Ctrl+C
ps> .\scripts\uninstall.ps1      # unload + remove the service and the driver file
```

`scripts\smoke.ps1` does the whole cycle: install, run the client for a few seconds, count the
events it received, unload, and fail if no event arrived or if a new bugcheck was recorded.

Reinstalling on the same boot can fail at the copy step (see limit 8): the previously loaded image
can stay mapped, so reboot before replacing `ramon.sys`.

A real capture from a Windows 11 VM (client output, first lines after connecting):

```
SUCCESS! Client connected to driver
Some(ImageLoadEvent { pid: 3784, image_base: 140713424125952, image_size: 196608, path: "\\Device\\HarddiskVolume3\\Windows\\System32\\ncrypt.dll" })
Some(ImageLoadEvent { pid: 3784, image_base: 140713295740928, image_size: 548864, path: "\\Device\\HarddiskVolume3\\Windows\\System32\\FWPUCLNT.DLL" })
Some(ProcessCreateEvent { pid: 6276, parent_id: 2976, create_time: 134399983997759131, path: "\\??\\C:\\WINDOWS\\SystemApps\\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\\CrossDeviceResume.exe", session: None, command_line: "\"C:\\WINDOWS\\SystemApps\\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\\CrossDeviceResume.exe\" /tileid MicrosoftWindows.Client.CBS_cw5n1h2txyewy!CrossDeviceResumeApp" })
Some(RegistrySetValueEvent { pid: 4788, tid: 4808, key_name: "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\Services\\bam\\State\\UserSettings\\S-1-5-21-...", value_name: "MicrosoftWindows.Client.CBS_cw5n1h2txyewy", data_type: 3, data: [164, 134, 255, 199, 18, 124, 221, 1, 0, 0, 0, 0] })
...
```

In that run the filter attached to four volumes and the client received 713 events in ~5 s
(image loads, process creates, registry writes). `fltmc filters` showed `ramon` at altitude 345102.

## Limits (not production)

This is an example. What that means concretely:

1. **Global state.** State is process-wide: one driver instance, no per-volume or per-client
   isolation, and no cleanup ordering beyond the unload callback. Module state lives in `Locked<T>`
   (`src/locked.rs`: a `FAST_MUTEX` and its data, reachable only through a guard) or in
   `SpinLocked<T>` (`src/spinlock.rs`: the same for state read at DISPATCH), plus a few lock-free
   atomics and one raw-pointer callout state. There is **no `static mut`** and no
   `static_mut_refs` allowance in the driver. A production driver would hang the same state off the
   filter/instance contexts (`FltAllocateContext`) or the device object, which would also allow more
   than one instance.
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
7. **The WFP callout no longer limits reloads.** The teardown copies what it needs under the state
   lock and calls the WFP APIs after releasing it; the callouts associate no flow contexts (they
   were never read and `FwpsCalloutUnregisterById0` returns `STATUS_DEVICE_BUSY` while one lives),
   and every teardown status is logged. A registry-callback cookie bug that bugchecked 0xCE on
   unload (an out-parameter declared as `&LARGE_INTEGER`, so the compiler stored zero and the
   callback survived the image) is fixed. A full load → unload → load → unload cycle now works in
   one boot and `ramon.sys` can be replaced. The communication port accepts only an elevated process
   whose image name starts with `ramon-client`, so renaming the client prevents it from connecting
   (a name/elevation check, not a cryptographic handshake). Details:
   [docs/verification.md](docs/verification.md).
8. **Mirage and MOTA are detection aids, not boundaries.** Mirage hides a decoy from one process
   tree by rewriting the create path; a determined caller can reach the file by other means. MOTA
   keys on `FileId`, so it sees reopens but not a copy made through an untagged process first.

If you need a production-grade component here, treat this as the reference implementation of the
callbacks and the protocol, not as the component.

## Editions

| Edition | Year | How it was written | Repository |
|---|---|---|---|
| 1 | 2025 | By hand, no AI | [adkum/ramon-rs-legacy](https://github.com/radkum/ramon-rs-legacy) |
| 2 | 2026 | AI-assisted rewrite and extension | this repository |

Edition 1 is the original minifilter prototype (file-create, process, image-load and registry
events over a minifilter communication port). This edition keeps that protocol and extends it with
the techniques described above.
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
