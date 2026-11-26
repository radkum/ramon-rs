# Hand-declared kernel ABI

`km-api-sys` (from `windows-kernel-rs`) covers the core WDM/fltmgr surface used by the original
example, but not everything this driver needs. The symbols below are declared locally with
`extern "system"` and linked against the WDK import libraries configured in `ramon-km/build.rs`
(`ntoskrnl.lib`, `fltMgr.lib`, `fwpkclnt.lib`, `Ndis.lib`).

These declarations are pinned to the WDK ABI as published in the headers named below, and are
**not** version-checked at build time. If you build against a different WDK, verify each prototype
against the header; a mismatch is silent at compile time and undefined at run time.

| Symbol | Header | Availability | Used by |
|---|---|---|---|
| `PsCreateSystemThread`, `PsTerminateSystemThread`, `PsGetCurrentThread` | `wdm.h` | NT 4+ | `send_message.rs`, `net.rs` |
| `PsGetProcessCreateTimeQuadPart` | `ntifs.h` (undocumented) | NT 6+ | `process_notify.rs`, `object_notify.rs` |
| `PsGetProcessId`, `PsGetProcessImageFileName` | `ntifs.h` | NT 6+ | `object_notify.rs`, `mota.rs` |
| `PsReferencePrimaryToken`, `PsDereferencePrimaryToken`, `SeTokenIsAdmin` | `ntifs.h` / `ntddk.h` | NT 6+ | `guardrail.rs` |
| `ObRegisterCallbacks`, `ObUnRegisterCallbacks` | `wdm.h` | Windows 7+ | `object_notify.rs` |
| `FltObjectDereference`, `FltGetFileNameInformationUnsafe` | `fltKernel.h` | Vista+ | `file_monitor.rs` |
| `FltAllocateContext`, `FltSetStreamContext`, `FltGetStreamContext`, `FltReleaseContext`, `FltQueryInformationFile` | `fltKernel.h` | Vista+ | `mota.rs` |
| `FltSetCallbackDataDirty` | `fltKernel.h` | Vista+ | `mirage.rs` |
| `IoReplaceFileObjectName` | `ntifs.h` | Windows Vista+ | `mirage.rs` |
| `MmCopyMemory` | `ntifs.h` | Windows 8+ | `registry_notify.rs`, `minifilter.rs` |
| `IoCreateDevice`, `IoDeleteDevice` | `wdm.h` | NT 4+ | `net.rs` |
| `KeInitializeSpinLock`, `KeAcquireSpinLockRaiseToDpc`, `KeReleaseSpinLock` | `wdm.h` | NT 4+ | `spinlock.rs` |
| `KeInitializeEvent`, `KeSetEvent`, `KeClearEvent`, `KeWaitForSingleObject` | `wdm.h` | NT 4+ | `send_message.rs`, `net.rs` |
| `ZwWaitForSingleObject`, `ZwClose` | `wdm.h` | NT 4+ | `send_message.rs`, `net.rs` |
| `KeQueryInterruptTimePrecise` | `wdm.h` | Windows 8+ | `send_message.rs` |
| `KeSetPriorityThread` | undocumented (exported by `ntoskrnl`) | NT 6+ | `send_message.rs` |
| `DbgPrintEx` | `wdm.h` | NT 4+ | `logger.rs` |
| `FwpmEngineOpen0`, `FwpmEngineClose0`, `FwpmSubLayerAdd0`, `FwpmSubLayerDeleteByKey0`, `FwpmCalloutAdd0`, `FwpmCalloutDeleteByKey0`, `FwpmFilterAdd0`, `FwpmFilterDeleteById0` | `fwpmk.h` | Windows 7+ | `net.rs` |
| `FwpsCalloutRegister0`, `FwpsCalloutUnregisterById0` | `fwpsk.h` | Windows 7+ | `net.rs` |
| `CmRegisterCallbackEx` (local override) | `wdm.h` | Windows Vista+ | `lib.rs` |

Notes:

- **Out-parameters must be pointers.** `km-api-sys` declares `CmRegisterCallbackEx`'s `Cookie` as
  `&LARGE_INTEGER`. That is an out parameter: with a shared reference the optimizer is allowed to
  assume the callee does not write through it, and it compiled `*G_COOKIE.lock() = cookie` to a
  store of zero. `CmUnRegisterCallback(0)` then failed silently and the registry callback survived
  the image unload (bugcheck 0xCE). The driver declares the function locally with
  `Cookie: *mut LARGE_INTEGER`; do the same for any other out-parameter that `km-api-sys` types as
  `&T`.

- Undocumented symbols (`PsGetProcessCreateTimeQuadPart`, `KeSetPriorityThread`) are exported by
  `ntoskrnl.exe` but are not contractual. They are used because the documented alternatives are
  either the same symbol or require an allocation.
- WFP structures (`FWPS_INCOMING_VALUES`, `FWPS_INCOMING_METADATA_VALUES`, `FWPM_*`) are mirrored
  field-by-field in `net.rs` because the generated bindings are not part of `km-api-sys`. Field
  offsets are read by index constants (`FIELD_*`); recheck them against `fwpsu.h` for your WDK.
- If a target OS lacks one of these exports, `DriverEntry` fails at load (`STATUS_PROCEDURE_NOT_FOUND`)
  rather than at run time — the loader resolves every import before the driver's entry point runs.
