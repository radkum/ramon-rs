//! WFP callout: egress per agent tree. A callout registered on `ALE_AUTH_CONNECT_V4/V6` and
//! `ALE_FLOW_ESTABLISHED_V4/V6` looks a process up in the session tree and, for a tagged process,
//! reports one `NetFlowEvent` per flow (5-tuple; for UDP the first datagram to the destination).
//! Filtering is by session tag in the kernel: an untagged process costs one tree lookup and returns.
//!
//! The classify runs at IRQL <= DISPATCH_LEVEL, so it does no allocation, no I/O and no blocking:
//! it only reads the NonPaged tree under a spinlock and pushes a fixed-size record into a static
//! ring. A dedicated thread drains the ring at PASSIVE_LEVEL and hands each event to `send_message`.
//! The callout is inspection-only (`FWP_ACTION_CALLOUT_INSPECTION`): it never changes the firewall's
//! decision. Blocking (`FWP_ACTION_BLOCK` on `ALE_AUTH_CONNECT`) is a separate product decision and
//! would require terminating filters. The WFP API is not in `km-api-sys`, so the structures and
//! functions are declared here against the WDK ABI (`fwpsk.h`/`fwpmk.h`).

use core::{
    ffi::c_void,
    mem,
    ptr::{addr_of_mut, null, null_mut},
    sync::atomic::{AtomicU32, AtomicUsize, Ordering},
};

use ariadne::{AgentKind, ProcessKey, SessionTag};
use common::event::{
    net_flow::{NetFlowEvent, DIRECTION_OUTBOUND},
    Event,
};
use kernel_macros::NT_SUCCESS;
use kernel_string::UNICODE_STRING;
use km_api_sys::wmd::{KeInitializeEvent, ZwClose};
use winapi::{
    km::wdm::{SynchronizationEvent, DEVICE_OBJECT, DRIVER_OBJECT, KEVENT},
    shared::{
        ntdef::{HANDLE, NTSTATUS, PVOID, TRUE},
        ntstatus::{STATUS_NOT_FOUND, STATUS_SUCCESS},
    },
};

use crate::{
    locked::Locked, notifiers::session_tag_of, send_message::send_message, spinlock::SpinLocked,
};

// ---------------------------------------------------------------- WFP ABI

#[repr(C)]
#[derive(Clone, Copy)]
struct Guid {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [u8; 8],
}

const fn guid(d1: u32, d2: u16, d3: u16, d4: [u8; 8]) -> Guid {
    Guid { data1: d1, data2: d2, data3: d3, data4: d4 }
}

#[repr(C)]
struct FwpmDisplayData {
    name: *mut u16,
    description: *mut u16,
}

#[repr(C)]
struct FwpByteBlob {
    size: u32,
    data: *mut u8,
}

#[repr(C)]
struct FwpmSession {
    session_key: Guid,
    display_data: FwpmDisplayData,
    flags: u32,
    txn_wait_timeout_in_msec: u32,
    process_id: u32,
    sid: PVOID,
    username: *mut u16,
    kernel_mode: i32,
}

#[repr(C)]
struct FwpmSublayer {
    sub_layer_key: Guid,
    display_data: FwpmDisplayData,
    flags: u32,
    provider_key: *mut Guid,
    provider_data: FwpByteBlob,
    weight: u16,
}

#[repr(C)]
struct FwpmCallout {
    callout_key: Guid,
    display_data: FwpmDisplayData,
    flags: u32,
    provider_key: *mut Guid,
    provider_data: FwpByteBlob,
    applicable_layer: Guid,
    callout_id: u32,
}

// FWP_VALUE0: FWP_DATA_TYPE (u32) then a union; the union is 8 bytes (a pointer/uint64)
#[repr(C)]
struct FwpValue {
    type_: u32,
    data: u64,
}

// FWPM_ACTION0: FWP_ACTION_TYPE (u32) then union { GUID filterType; GUID calloutKey; }
#[repr(C)]
struct FwpmAction {
    action_type: u32,
    callout_key: Guid,
}

// FWPM_FILTER0: the `action` union is 16 bytes (a GUID), so it is declared as `Guid`
#[repr(C)]
struct FwpmFilter {
    filter_key: Guid,
    display_data: FwpmDisplayData,
    flags: u32,
    provider_key: *mut Guid,
    provider_data: FwpByteBlob,
    layer_key: Guid,
    sub_layer_key: Guid,
    weight: FwpValue,
    num_filter_conditions: u32,
    filter_condition: *mut c_void,
    action: FwpmAction,
    // union { UINT64 rawContext; GUID providerContextKey; }: 16 bytes, 8-aligned
    context: [u64; 2],
    reserved: *mut Guid,
    filter_id: u64,
    effective_weight: FwpValue,
}

#[repr(C)]
struct FwpsCallout {
    callout_key: Guid,
    flags: u32,
    classify_fn: Option<FwpsClassifyFn>,
    notify_fn: Option<FwpsNotifyFn>,
    flow_delete_fn: Option<FwpsFlowDeleteFn>,
}

#[repr(C)]
struct FwpsIncomingValue {
    value: FwpValue,
}

#[repr(C)]
struct FwpsIncomingValues {
    layer_id: u16,
    value_count: u32,
    incoming_value: *mut FwpsIncomingValue,
}

#[repr(C)]
struct FwpsDiscardMetadata {
    discard_module: u32,
    discard_reason: u32,
    filter_id: u64,
}

// only up to `process_id`; the rest of FWPS_INCOMING_METADATA_VALUES0 is not read
#[allow(dead_code)]
#[repr(C)]
struct FwpsIncomingMetadata {
    current_metadata_values: u32,
    flags: u32,
    reserved: u64,
    discard_metadata: FwpsDiscardMetadata,
    flow_handle: u64,
    ip_header_size: u32,
    transport_header_size: u32,
    process_path: *mut FwpByteBlob,
    token: u64,
    process_id: u64,
}

#[repr(C)]
struct FwpsClassifyOut {
    action_type: u32,
    out_context: u64,
    filter_id: u64,
    rights: u32,
    flags: u32,
    reserved: u32,
}

type FwpsClassifyFn = extern "system" fn(
    *const FwpsIncomingValues,
    *const FwpsIncomingMetadata,
    *mut c_void,
    *const c_void,
    u64,
    *mut FwpsClassifyOut,
);
type FwpsNotifyFn = extern "system" fn(u32, *const Guid, *mut c_void) -> NTSTATUS;
type FwpsFlowDeleteFn = extern "system" fn(u16, u32, u64);

#[link(name = "fwpkclnt")]
extern "system" {
    fn FwpmEngineOpen0(
        server_name: *const u16,
        authn_service: u32,
        auth_identity: PVOID,
        session: *const FwpmSession,
        engine: *mut HANDLE,
    ) -> NTSTATUS;
    fn FwpmEngineClose0(engine: HANDLE) -> NTSTATUS;
    fn FwpmSubLayerAdd0(engine: HANDLE, sub_layer: *const FwpmSublayer, sd: PVOID) -> NTSTATUS;
    fn FwpmSubLayerDeleteByKey0(engine: HANDLE, key: *const Guid) -> NTSTATUS;
    fn FwpmCalloutAdd0(
        engine: HANDLE,
        callout: *const FwpmCallout,
        sd: PVOID,
        id: *mut u32,
    ) -> NTSTATUS;
    fn FwpmCalloutDeleteByKey0(engine: HANDLE, key: *const Guid) -> NTSTATUS;
    fn FwpmFilterAdd0(
        engine: HANDLE,
        filter: *const FwpmFilter,
        sd: PVOID,
        id: *mut u64,
    ) -> NTSTATUS;
    fn FwpmFilterDeleteById0(engine: HANDLE, id: u64) -> NTSTATUS;
    fn FwpsCalloutRegister0(
        device: *mut c_void,
        callout: *const FwpsCallout,
        callout_id: *mut u32,
    ) -> NTSTATUS;
    fn FwpsCalloutUnregisterById0(callout_id: u32) -> NTSTATUS;
}

// not declared in km-api-sys
extern "system" {
    fn IoCreateDevice(
        driver: *mut DRIVER_OBJECT,
        extension_size: u32,
        name: *const UNICODE_STRING,
        device_type: u32,
        characteristics: u32,
        exclusive: u8,
        device: *mut *mut DEVICE_OBJECT,
    ) -> NTSTATUS;
    fn IoDeleteDevice(device: *mut DEVICE_OBJECT);
    fn KeSetEvent(event: *mut KEVENT, increment: i32, wait: u8) -> i32;
    fn KeDelayExecutionThread(wait_mode: u32, alertable: u8, interval: *const i64) -> NTSTATUS;
    fn KeWaitForSingleObject(
        object: PVOID,
        reason: u32,
        mode: i8,
        alertable: u8,
        timeout: *const i64,
    ) -> NTSTATUS;
    fn PsCreateSystemThread(
        thread: *mut HANDLE,
        access: u32,
        attributes: *mut winapi::shared::ntdef::OBJECT_ATTRIBUTES,
        process: HANDLE,
        client_id: PVOID,
        start: extern "system" fn(PVOID),
        context: PVOID,
    ) -> NTSTATUS;
    fn PsTerminateSystemThread(status: NTSTATUS) -> NTSTATUS;
    fn ZwWaitForSingleObject(handle: HANDLE, alertable: u8, timeout: *const i64) -> NTSTATUS;
}

// ---------------------------------------------------------------- constants

// WFP rejects a null display name (`STATUS_FWP_NULL_DISPLAY_NAME`); the wide string must stay valid
// for the lifetime of the objects, so it lives in a static
static WFP_NAME: [u16; 10] =
    [0x0052, 0x0061, 0x006d, 0x006f, 0x006e, 0x0020, 0x0057, 0x0046, 0x0050, 0x0000];

fn display_data() -> FwpmDisplayData {
    FwpmDisplayData { name: WFP_NAME.as_ptr() as *mut u16, description: null_mut() }
}

const RPC_C_AUTHN_WINNT: u32 = 10;
const FWPM_SESSION_FLAG_DYNAMIC: u32 = 0x0000_0001;
const FWP_ACTION_CALLOUT_INSPECTION: u32 = 0x0000_6004;
const FWP_ACTION_PERMIT: u32 = 0x0000_1002;
const FWPS_RIGHT_ACTION_WRITE: u32 = 0x0000_0001;
const FILE_DEVICE_UNKNOWN: u32 = 0x0000_0022;
const DO_DEVICE_INITIALIZING: u32 = 0x0000_0080;

// indices into FWPS_FIELDS_ALE_* (identical across the four layers we use)
const FIELD_LOCAL_ADDRESS: usize = 2;
const FIELD_LOCAL_PORT: usize = 4;
const FIELD_PROTOCOL: usize = 5;
const FIELD_REMOTE_ADDRESS: usize = 6;
const FIELD_REMOTE_PORT: usize = 7;
const FIELD_DIRECTION: usize = 12;

const ALE_AUTH_CONNECT_V4: Guid =
    guid(0xc38d_57d1, 0x05a7, 0x4c33, [0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82]);
const ALE_AUTH_CONNECT_V6: Guid =
    guid(0x4a72_393b, 0x319f, 0x44bc, [0x84, 0xc3, 0xba, 0x54, 0xdc, 0xb3, 0xb6, 0xb4]);
const ALE_FLOW_ESTABLISHED_V4: Guid =
    guid(0xaf80_470a, 0x5596, 0x4c13, [0x99, 0x92, 0x53, 0x9e, 0x6f, 0xe5, 0x79, 0x67]);
const ALE_FLOW_ESTABLISHED_V6: Guid =
    guid(0x7021_d2b3, 0xdfa4, 0x406e, [0xaf, 0xeb, 0x6a, 0xfa, 0xf7, 0xe7, 0x0e, 0xfd]);

const LAYERS: [Guid; 4] =
    [ALE_AUTH_CONNECT_V4, ALE_AUTH_CONNECT_V6, ALE_FLOW_ESTABLISHED_V4, ALE_FLOW_ESTABLISHED_V6];
// the filter engine orders filters by weight; a distinct GUID per layer keeps them apart
const CALLBACK_KEYS: [Guid; 4] = [
    guid(0x5a1b_0001, 0x0001, 0x4000, [0x9e, 0x01, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66]),
    guid(0x5a1b_0002, 0x0001, 0x4000, [0x9e, 0x01, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66]),
    guid(0x5a1b_0003, 0x0001, 0x4000, [0x9e, 0x01, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66]),
    guid(0x5a1b_0004, 0x0001, 0x4000, [0x9e, 0x01, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66]),
];
const FILTER_KEYS: [Guid; 4] = [
    guid(0x5a1b_0011, 0x0001, 0x4000, [0x9e, 0x01, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66]),
    guid(0x5a1b_0012, 0x0001, 0x4000, [0x9e, 0x01, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66]),
    guid(0x5a1b_0013, 0x0001, 0x4000, [0x9e, 0x01, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66]),
    guid(0x5a1b_0014, 0x0001, 0x4000, [0x9e, 0x01, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66]),
];
const SUBLAYER_KEY: Guid =
    guid(0x5a1b_1000, 0x0001, 0x4000, [0x9e, 0x01, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);

// ---------------------------------------------------------------- ring queue

// fixed-size so a DISPATCH_LEVEL classify never allocates; the drain thread serializes at PASSIVE
const RING_LEN: usize = 4096;

#[derive(Clone, Copy)]
struct NetEntry {
    pid: u32,
    session: SessionTag,
    direction: u8,
    family: u8,
    protocol: u8,
    local_addr: [u8; 16],
    remote_addr: [u8; 16],
    local_port: u16,
    remote_port: u16,
}

const EMPTY_SESSION: SessionTag = SessionTag {
    root: ProcessKey { pid: 0, create_time: 0 },
    kind: AgentKind::Claude,
    parent_session: None,
};
const EMPTY_ENTRY: NetEntry = NetEntry {
    pid: 0,
    session: EMPTY_SESSION,
    direction: 0,
    family: 0,
    protocol: 0,
    local_addr: [0; 16],
    remote_addr: [0; 16],
    local_port: 0,
    remote_port: 0,
};

struct NetRing {
    entries: [NetEntry; RING_LEN],
    head: usize,
    tail: usize,
    len: usize,
    dropped: u32,
    stop: bool,
    wake: KEVENT,
}

static G_RING: SpinLocked<NetRing> = SpinLocked::new(NetRing {
    entries: [EMPTY_ENTRY; RING_LEN],
    head: 0,
    tail: 0,
    len: 0,
    dropped: 0,
    stop: false,
    // a zeroed KEVENT is valid only after KeInitializeEvent, which start() does before use
    wake: unsafe { mem::zeroed() },
});
static G_NET_THREAD: AtomicUsize = AtomicUsize::new(0);
// set by start(): stop() must not lock an uninitialized state if the driver never started WFP
static G_STARTED: AtomicUsize = AtomicUsize::new(0);

// the event lives in the static for the driver's lifetime; the drain thread waits on it without
// holding the spinlock
fn wake_ptr() -> *mut KEVENT {
    unsafe { addr_of_mut!((*G_RING.get_ptr()).wake) }
}

/// Runs at IRQL <= DISPATCH: only touches the ring under the spinlock.
unsafe fn enqueue(entry: NetEntry) {
    let wake = {
        let mut ring = G_RING.lock();
        if ring.len == RING_LEN {
            ring.dropped = ring.dropped.wrapping_add(1);
            return;
        }
        let head = ring.head;
        ring.entries[head] = entry;
        ring.head = (head + 1) % RING_LEN;
        ring.len += 1;
        &mut ring.wake as *mut KEVENT
    };
    // raw pointer on purpose: concurrent classifies on different CPUs must not form `&mut`
    KeSetEvent(wake, 0, 0);
}

extern "system" fn drain_thread(_context: PVOID) {
    unsafe {
        drain_loop();
        PsTerminateSystemThread(STATUS_SUCCESS);
    }
}

unsafe fn drain_loop() {
    let wake = wake_ptr();
    loop {
        KeWaitForSingleObject(wake as PVOID, 0, 0, 0, null());
        loop {
            let entry = {
                let mut ring = G_RING.lock();
                if ring.len == 0 {
                    None
                } else {
                    let entry = ring.entries[ring.tail];
                    ring.tail = (ring.tail + 1) % RING_LEN;
                    ring.len -= 1;
                    Some(entry)
                }
            };
            match entry {
                Some(entry) => emit(entry),
                None => break,
            }
        }
        if G_RING.lock().stop {
            return;
        }
    }
}

fn emit(entry: NetEntry) {
    let event = NetFlowEvent::new(
        entry.pid,
        entry.session,
        entry.direction,
        entry.family,
        entry.protocol,
        entry.local_addr,
        entry.remote_addr,
        entry.local_port,
        entry.remote_port,
    );
    send_message(event.serialize().unwrap_or_default());
}

// ---------------------------------------------------------------- classify

// No flow contexts are associated. `FwpsCalloutUnregisterById0` returns STATUS_DEVICE_BUSY while
// any flow still has a context from the callout, and the documented fix is FwpsFlowRemoveContext0
// per flow - which would require tracking every live flow id. The context was never read (the
// event carries a fresh tag lookup at ALE_FLOW_ESTABLISHED), so not associating one keeps the
// unload deterministic and removes the only way the runtime callout could stay registered.

fn value_u32(values: &[FwpsIncomingValue], index: usize) -> u32 {
    values.get(index).map_or(0, |value| value.value.data as u32)
}

fn value_u16(values: &[FwpsIncomingValue], index: usize) -> u16 {
    values.get(index).map_or(0, |value| value.value.data as u16)
}

fn value_u8(values: &[FwpsIncomingValue], index: usize) -> u8 {
    values.get(index).map_or(0, |value| value.value.data as u8)
}

fn value_addr(values: &[FwpsIncomingValue], index: usize, family: u8, out: &mut [u8; 16]) {
    let Some(value) = values.get(index) else {
        return;
    };
    if family == 4 {
        // WFP hands the V4 address as a host-order UINT32; `to_be_bytes` gives the dotted-quad bytes
        out[..4].copy_from_slice(&(value.value.data as u32).to_be_bytes());
    } else if value.value.data != 0 {
        let source = value.value.data as *const [u8; 16];
        out.copy_from_slice(unsafe { &*source });
    }
}

unsafe fn classify_impl(
    in_fixed: *const FwpsIncomingValues,
    in_meta: *const FwpsIncomingMetadata,
    classify_out: *mut FwpsClassifyOut,
    family: u8,
    established: bool,
) {
    if in_fixed.is_null() || in_meta.is_null() || classify_out.is_null() {
        return;
    }
    let fixed = &*in_fixed;
    let meta = &*in_meta;
    let out = &mut *classify_out;
    // inspection callout: always permit, never alter the firewall's own decision
    if out.rights & FWPS_RIGHT_ACTION_WRITE != 0 {
        out.action_type = FWP_ACTION_PERMIT;
    }
    // the ALE_AUTH_CONNECT layers only authorize the connection; nothing is remembered there
    if !established {
        return;
    }
    let pid = meta.process_id as u32;
    if pid == 0 || fixed.incoming_value.is_null() {
        return;
    }
    let Some(session) = session_tag_of(pid) else {
        return;
    };
    let values = core::slice::from_raw_parts(fixed.incoming_value, fixed.value_count as usize);
    let direction = value_u32(values, FIELD_DIRECTION) as u8;
    if direction != DIRECTION_OUTBOUND {
        return;
    }
    let mut local_addr = [0u8; 16];
    let mut remote_addr = [0u8; 16];
    value_addr(values, FIELD_LOCAL_ADDRESS, family, &mut local_addr);
    value_addr(values, FIELD_REMOTE_ADDRESS, family, &mut remote_addr);
    enqueue(NetEntry {
        pid,
        session,
        direction,
        family,
        protocol: value_u8(values, FIELD_PROTOCOL),
        local_addr,
        remote_addr,
        local_port: value_u16(values, FIELD_LOCAL_PORT),
        remote_port: value_u16(values, FIELD_REMOTE_PORT),
    });
}

extern "system" fn classify_auth_v4(
    fixed: *const FwpsIncomingValues,
    meta: *const FwpsIncomingMetadata,
    _layer_data: *mut c_void,
    _filter: *const c_void,
    _flow_context: u64,
    out: *mut FwpsClassifyOut,
) {
    unsafe { classify_impl(fixed, meta, out, 4, false) };
}

extern "system" fn classify_auth_v6(
    fixed: *const FwpsIncomingValues,
    meta: *const FwpsIncomingMetadata,
    _layer_data: *mut c_void,
    _filter: *const c_void,
    _flow_context: u64,
    out: *mut FwpsClassifyOut,
) {
    unsafe { classify_impl(fixed, meta, out, 6, false) };
}

extern "system" fn classify_flow_v4(
    fixed: *const FwpsIncomingValues,
    meta: *const FwpsIncomingMetadata,
    _layer_data: *mut c_void,
    _filter: *const c_void,
    _flow_context: u64,
    out: *mut FwpsClassifyOut,
) {
    unsafe { classify_impl(fixed, meta, out, 4, true) };
}

extern "system" fn classify_flow_v6(
    fixed: *const FwpsIncomingValues,
    meta: *const FwpsIncomingMetadata,
    _layer_data: *mut c_void,
    _filter: *const c_void,
    _flow_context: u64,
    out: *mut FwpsClassifyOut,
) {
    unsafe { classify_impl(fixed, meta, out, 6, true) };
}

extern "system" fn notify(
    _notify_type: u32,
    _filter_key: *const Guid,
    _filter: *mut c_void,
) -> NTSTATUS {
    STATUS_SUCCESS
}

const CLASSIFY_FNS: [FwpsClassifyFn; 4] =
    [classify_auth_v4, classify_auth_v6, classify_flow_v4, classify_flow_v6];
const CALLBACK_FLAGS: [u32; 4] = [0, 0, 0, 0];

// ---------------------------------------------------------------- registration

// registration state, touched only at load/unload (PASSIVE)
struct NetState {
    engine: HANDLE,
    device: *mut DEVICE_OBJECT,
    sublayer_added: bool,
    callout_registered: [bool; 4],
    callout_added: [bool; 4],
    filter_added: [bool; 4],
    filter_id: [u64; 4],
}

static G_NET: Locked<NetState> = Locked::new(NetState {
    engine: null_mut(),
    device: null_mut(),
    sublayer_added: false,
    callout_registered: [false; 4],
    callout_added: [false; 4],
    filter_added: [false; 4],
    filter_id: [0; 4],
});
// the runtime callout ids returned by FwpsCalloutRegister0; read only on the unload path
static G_CALLOUT_ID: [AtomicU32; 4] = [const { AtomicU32::new(0) }; 4];

unsafe fn register_callout(index: usize) -> NTSTATUS {
    let callout = FwpsCallout {
        callout_key: CALLBACK_KEYS[index],
        flags: CALLBACK_FLAGS[index],
        classify_fn: Some(CLASSIFY_FNS[index]),
        notify_fn: Some(notify),
        // no flow contexts are associated, so there is nothing to release on flow delete
        flow_delete_fn: None,
    };
    let mut id = 0u32;
    let device = G_NET.lock().device;
    let status = FwpsCalloutRegister0(device as *mut c_void, &callout, &mut id);
    if NT_SUCCESS!(status) {
        G_CALLOUT_ID[index].store(id, Ordering::Release);
        G_NET.lock().callout_registered[index] = true;
    }
    status
}

unsafe fn add_callout(index: usize) -> NTSTATUS {
    let callout = FwpmCallout {
        callout_key: CALLBACK_KEYS[index],
        display_data: display_data(),
        flags: 0,
        provider_key: null_mut(),
        provider_data: FwpByteBlob { size: 0, data: null_mut() },
        applicable_layer: LAYERS[index],
        callout_id: G_CALLOUT_ID[index].load(Ordering::Acquire),
    };
    let engine = G_NET.lock().engine;
    let status = FwpmCalloutAdd0(engine, &callout, null_mut(), null_mut());
    if NT_SUCCESS!(status) {
        G_NET.lock().callout_added[index] = true;
    }
    status
}

unsafe fn add_filter(index: usize) -> NTSTATUS {
    let filter = FwpmFilter {
        filter_key: FILTER_KEYS[index],
        display_data: display_data(),
        flags: 0,
        provider_key: null_mut(),
        provider_data: FwpByteBlob { size: 0, data: null_mut() },
        layer_key: LAYERS[index],
        sub_layer_key: SUBLAYER_KEY,
        // callout filters use auto-weight; an explicit FWP_UINT8 weight is rejected as invalid
        weight: FwpValue { type_: 0, data: 0 },
        num_filter_conditions: 0,
        filter_condition: null_mut(),
        action: FwpmAction {
            action_type: FWP_ACTION_CALLOUT_INSPECTION,
            callout_key: CALLBACK_KEYS[index],
        },
        context: [0; 2],
        reserved: null_mut(),
        filter_id: 0,
        effective_weight: FwpValue { type_: 0, data: 0 },
    };
    let mut id = 0u64;
    let engine = G_NET.lock().engine;
    let status = FwpmFilterAdd0(engine, &filter, null_mut(), &mut id);
    if NT_SUCCESS!(status) {
        let mut state = G_NET.lock();
        state.filter_added[index] = true;
        state.filter_id[index] = id;
    }
    status
}

unsafe fn open_engine() -> NTSTATUS {
    let session = FwpmSession {
        session_key: Guid { data1: 0, data2: 0, data3: 0, data4: [0; 8] },
        display_data: display_data(),
        flags: FWPM_SESSION_FLAG_DYNAMIC,
        txn_wait_timeout_in_msec: 0,
        process_id: 0,
        sid: null_mut(),
        username: null_mut(),
        kernel_mode: TRUE as i32,
    };
    let mut engine: HANDLE = null_mut();
    let status = FwpmEngineOpen0(null(), RPC_C_AUTHN_WINNT, null_mut(), &session, &mut engine);
    if NT_SUCCESS!(status) {
        G_NET.lock().engine = engine;
    }
    status
}

unsafe fn add_sublayer() -> NTSTATUS {
    let sublayer = FwpmSublayer {
        sub_layer_key: SUBLAYER_KEY,
        display_data: display_data(),
        flags: 0,
        provider_key: null_mut(),
        provider_data: FwpByteBlob { size: 0, data: null_mut() },
        weight: 0x0100,
    };
    let engine = G_NET.lock().engine;
    let status = FwpmSubLayerAdd0(engine, &sublayer, null_mut());
    if NT_SUCCESS!(status) {
        G_NET.lock().sublayer_added = true;
    }
    status
}

unsafe fn start_drain_thread() -> NTSTATUS {
    let mut thread: HANDLE = null_mut();
    let status = PsCreateSystemThread(
        &mut thread,
        0x0010_0000, // SYNCHRONIZE
        null_mut(),
        null_mut(),
        null_mut(),
        drain_thread,
        null_mut(),
    );
    if NT_SUCCESS!(status) {
        G_NET_THREAD.store(thread as usize, Ordering::Release);
    }
    status
}

/// Registers the callout, sublayer and filters and starts the drain thread. PASSIVE_LEVEL.
/// # Safety
/// `driver` is the DRIVER_OBJECT from DriverEntry.
pub(crate) unsafe fn start(driver: *mut DRIVER_OBJECT) -> NTSTATUS {
    G_RING.init();
    G_NET.init();
    // before any filter is live: a classify that fires during registration must not touch an
    // uninitialized event (`KeSetEvent` would be lost by the later `KeInitializeEvent`)
    {
        let mut ring = G_RING.lock();
        KeInitializeEvent(&mut ring.wake, SynchronizationEvent, 0);
    }
    G_STARTED.store(1, Ordering::Release);

    let mut device: *mut DEVICE_OBJECT = null_mut();
    let status = IoCreateDevice(driver, 0, null(), FILE_DEVICE_UNKNOWN, 0, 0, &mut device);
    if !NT_SUCCESS!(status) {
        log::warn!("wfp: IoCreateDevice failed. Status: 0x{:08x}", status);
        rollback();
        return status;
    }
    (*device).Flags &= !DO_DEVICE_INITIALIZING;
    G_NET.lock().device = device;

    let mut status = open_engine();
    if !NT_SUCCESS!(status) {
        log::warn!("wfp: FwpmEngineOpen0 failed. Status: 0x{:08x}", status);
        rollback();
        return status;
    }
    status = add_sublayer();
    if !NT_SUCCESS!(status) {
        log::warn!("wfp: FwpmSubLayerAdd0 failed. Status: 0x{:08x}", status);
        rollback();
        return status;
    }
    for index in 0..4 {
        status = register_callout(index);
        if !NT_SUCCESS!(status) {
            log::warn!("wfp: callout {} register failed. Status: 0x{:08x}", index, status);
            rollback();
            return status;
        }
        status = add_callout(index);
        if !NT_SUCCESS!(status) {
            log::warn!("wfp: callout {} add failed. Status: 0x{:08x}", index, status);
            rollback();
            return status;
        }
        status = add_filter(index);
        if !NT_SUCCESS!(status) {
            log::warn!("wfp: filter {} add failed. Status: 0x{:08x}", index, status);
            rollback();
            return status;
        }
    }
    status = start_drain_thread();
    if !NT_SUCCESS!(status) {
        log::warn!("wfp: drain thread failed. Status: 0x{:08x}", status);
        rollback();
        return status;
    }
    log::info!("wfp: callout registered on 4 ALE layers");
    STATUS_SUCCESS
}

unsafe fn stop_drain_thread() {
    G_RING.lock().stop = true;
    let thread = G_NET_THREAD.swap(0, Ordering::AcqRel) as HANDLE;
    if !thread.is_null() {
        KeSetEvent(wake_ptr(), 0, 0);
        ZwWaitForSingleObject(thread, 0, null());
        ZwClose(thread);
    }
}

const STATUS_DEVICE_BUSY: NTSTATUS = 0xC000_004Fu32 as NTSTATUS;
const FWP_E_CALLOUT_NOT_FOUND: NTSTATUS = 0x8032_0001u32 as NTSTATUS;
const FWP_E_FILTER_NOT_FOUND: NTSTATUS = 0x8032_0003u32 as NTSTATUS;
const FWP_E_SUBLAYER_NOT_FOUND: NTSTATUS = 0x8032_0007u32 as NTSTATUS;
const FWP_E_IN_USE: NTSTATUS = 0x8032_000Au32 as NTSTATUS;

/// Runs one teardown call, retrying transient busy/in-use statuses at PASSIVE_LEVEL.
/// Returns `STATUS_SUCCESS` on success or an already-deleted object (`not_found`).
macro_rules! teardown {
    ($step:expr, $not_found:expr, $alt_not_found:expr, $call:expr) => {{
        let mut result = STATUS_SUCCESS;
        for attempt in 0..10 {
            let status = $call;
            if NT_SUCCESS!(status) || status == $not_found || status == $alt_not_found {
                break;
            }
            if status != STATUS_DEVICE_BUSY && status != FWP_E_IN_USE {
                log::warn!("wfp: {} failed. Status: 0x{:08x}", $step, status);
                result = status;
                break;
            }
            if attempt == 9 {
                log::warn!("wfp: {} still busy. Status: 0x{:08x}", $step, status);
                result = status;
                break;
            }
            let interval: i64 = -10 * 10_000;
            KeDelayExecutionThread(0, 0, &interval);
        }
        result
    }};
}

/// Cleans up a partially started WFP state; logs a failure instead of hiding it.
unsafe fn rollback() {
    let status = stop();
    if !NT_SUCCESS!(status) {
        log::warn!("wfp: rollback incomplete. Status: 0x{:08x}", status);
    }
}

/// Stops the drain thread and releases the WFP objects. PASSIVE_LEVEL.
///
/// The WFP teardown calls require PASSIVE_LEVEL, and `Locked::lock` holds the FAST_MUTEX at
/// APC_LEVEL: everything needed is copied under the lock, which is then dropped, and the calls run
/// outside it. Holding the lock here made every call return STATUS_NOT_SUPPORTED and left the
/// callout registration pinning the driver image until reboot.
///
/// Returns a failure if any object could not be released; the caller must then keep the image
/// loaded (an unloaded image with a live callout/filter is the 0xCE class of bug).
pub(crate) unsafe fn stop() -> NTSTATUS {
    // start() never ran: nothing to tear down, and the locks were never initialized
    if G_STARTED.load(Ordering::Acquire) == 0 {
        return STATUS_SUCCESS;
    }
    // stop the drain thread first: after this nothing calls send_message for a net event
    stop_drain_thread();
    let (
        engine,
        device,
        filter_added,
        filter_id,
        callout_added,
        callout_registered,
        sublayer_added,
    ) = {
        let state = G_NET.lock();
        (
            state.engine,
            state.device,
            state.filter_added,
            state.filter_id,
            state.callout_added,
            state.callout_registered,
            state.sublayer_added,
        )
    };
    let mut failure = STATUS_SUCCESS;
    macro_rules! remember {
        ($status:expr) => {{
            let status = $status;
            if !NT_SUCCESS!(status) && NT_SUCCESS!(failure) {
                failure = status;
            }
        }};
    }
    if !engine.is_null() {
        for index in 0..4 {
            if filter_added[index] {
                let status = teardown!(
                    "FwpmFilterDeleteById0",
                    FWP_E_FILTER_NOT_FOUND,
                    STATUS_SUCCESS,
                    FwpmFilterDeleteById0(engine, filter_id[index])
                );
                remember!(status);
                if NT_SUCCESS!(status) {
                    G_NET.lock().filter_added[index] = false;
                }
            }
            if callout_added[index] {
                let status = teardown!(
                    "FwpmCalloutDeleteByKey0",
                    FWP_E_CALLOUT_NOT_FOUND,
                    STATUS_SUCCESS,
                    FwpmCalloutDeleteByKey0(engine, &CALLBACK_KEYS[index])
                );
                remember!(status);
                if NT_SUCCESS!(status) {
                    G_NET.lock().callout_added[index] = false;
                }
            }
        }
        // no flow contexts are associated, so this cannot return STATUS_DEVICE_BUSY
        for index in 0..4 {
            if callout_registered[index] {
                let id = G_CALLOUT_ID[index].load(Ordering::Acquire);
                let status = teardown!(
                    "FwpsCalloutUnregisterById0",
                    FWP_E_CALLOUT_NOT_FOUND,
                    STATUS_NOT_FOUND,
                    FwpsCalloutUnregisterById0(id)
                );
                remember!(status);
                if NT_SUCCESS!(status) {
                    G_NET.lock().callout_registered[index] = false;
                    G_CALLOUT_ID[index].store(0, Ordering::Release);
                }
            }
        }
        if sublayer_added {
            let status = teardown!(
                "FwpmSubLayerDeleteByKey0",
                FWP_E_SUBLAYER_NOT_FOUND,
                STATUS_SUCCESS,
                FwpmSubLayerDeleteByKey0(engine, &SUBLAYER_KEY)
            );
            remember!(status);
            if NT_SUCCESS!(status) {
                G_NET.lock().sublayer_added = false;
            }
        }
        // closing the engine while an earlier delete failed would invalidate the handle a retry needs
        if NT_SUCCESS!(failure) {
            let status = teardown!(
                "FwpmEngineClose0",
                STATUS_SUCCESS,
                STATUS_SUCCESS,
                FwpmEngineClose0(engine)
            );
            remember!(status);
            if NT_SUCCESS!(status) {
                G_NET.lock().engine = null_mut();
            }
        }
    }
    if !NT_SUCCESS!(failure) {
        // G_STARTED and the not-yet-cleared fields stay set so a retry can finish; do not delete the
        // device or reset the ring while a callout/filter may still reference this image
        log::error!("wfp: teardown incomplete 0x{:08x}; keeping the image loaded", failure);
        return failure;
    }
    G_STARTED.store(0, Ordering::Release);
    let mut state = G_NET.lock();
    state.filter_id = [0; 4];
    for id in G_CALLOUT_ID.iter() {
        id.store(0, Ordering::Release);
    }
    drop(state);
    if !device.is_null() {
        IoDeleteDevice(device);
        G_NET.lock().device = null_mut();
    }
    let dropped = {
        let mut ring = G_RING.lock();
        let dropped = ring.dropped;
        ring.dropped = 0;
        dropped
    };
    if dropped != 0 {
        log::warn!("wfp: net events dropped (ring full): {}", dropped);
    }
    {
        let mut ring = G_RING.lock();
        ring.head = 0;
        ring.tail = 0;
        ring.len = 0;
        ring.stop = false;
    }
    STATUS_SUCCESS
}
