use std::{ffi::c_void, mem, path::Path, ptr::null_mut, sync::Arc};

use ansi_term::Colour::Green;
use common::{
    constants::COMM_PORT_NAME,
    event::{
        get_event_type, image_load::ImageLoadEvent, process_create::ProcessCreateEvent,
        registry_set_value::RegistrySetValueEvent, Event, FileCreateEvent,
    },
    handshake,
};
use console::Term;
use widestring::u16cstr;
use windows_sys::Win32::{
    Foundation::STATUS_SUCCESS,
    Storage::InstallableFileSystems::{
        FilterConnectCommunicationPort, FilterGetMessage, FILTER_MESSAGE_HEADER,
    },
};

use crate::{
    error::DetectionError,
    error_msg::{print_hr_result, print_last_error},
    handle_wrapper::SmartHandle,
    rade_detection::{self, Detector},
};

#[tokio::main]
pub async fn start_detection() {
    let port_name = u16cstr!(COMM_PORT_NAME).as_ptr();
    let Some(connection_port) = init_port(port_name) else {
        return;
    };

    let _ = ansi_term::enable_ansi_support();
    println!("{} Client connected to driver", Green.paint("SUCCESS!"));

    let detector = init_detector();
    message_loop(connection_port, detector);

    //CloseHandle(h_connection_port); ??
}

fn init_detector() -> Option<Detector> {
    let Some(dir) = std::env::var_os("RAMON_RADE_RULES") else {
        println!("RADE detection disabled (RAMON_RADE_RULES not set)");
        return None;
    };
    let dir = Path::new(&dir);
    match Detector::from_rules_dir(dir) {
        Ok(detector) => {
            println!("RADE detection enabled (rules: {})", dir.display());
            Some(detector)
        },
        Err(e) => {
            eprintln!("RADE rules from {} not loaded: {e}", dir.display());
            None
        },
    }
}

fn report_hits(detector: &Detector, event: rade::Event) {
    for hit in detector.evaluate(event) {
        match &hit.name {
            Some(name) => println!("RADE alert: {name} ({})", hit.id),
            None => println!("RADE alert: {}", hit.id),
        }
    }
}

fn init_port(port_name: *const u16) -> Option<SmartHandle> {
    let mut connection_port = SmartHandle::new();

    // handshake: prove knowledge of the shared key over a fresh nonce (see common::handshake)
    let Some(nonce) = random_nonce() else {
        eprintln!("RtlGenRandom (SystemFunction036) failed");
        return None;
    };
    let proof = handshake::make_proof(handshake::port_key(), &nonce);

    let hr = unsafe {
        FilterConnectCommunicationPort(
            port_name,
            0,
            proof.as_ptr() as *const c_void,
            proof.len() as u16,
            null_mut(),
            connection_port.as_mut_ref() as *mut isize,
        )
    };

    if hr != STATUS_SUCCESS {
        println!("Failed to connect");
        print_hr_result("", hr);
        print_last_error("");
        None
    } else {
        Some(connection_port)
    }
}

#[link(name = "advapi32")]
extern "system" {
    // RtlGenRandom: the OS CSPRNG, for the per-connect nonce
    fn SystemFunction036(buffer: *mut u8, length: u32) -> u8;
}

fn random_nonce() -> Option<[u8; handshake::NONCE_LEN]> {
    let mut nonce = [0u8; handshake::NONCE_LEN];
    let ok = unsafe { SystemFunction036(nonce.as_mut_ptr(), nonce.len() as u32) };
    (ok != 0).then_some(nonce)
}
fn message_loop(connection_port: SmartHandle, detector: Option<Detector>) {
    let arc_connection_port = Arc::new(connection_port);

    let _t = tokio::spawn(async move {
        loop {
            if let Err(e) = process_message(arc_connection_port.clone(), detector.as_ref()).await {
                eprintln!("{}", e);
            }
        }
    });

    let stdout = Term::buffered_stdout();
    loop {
        if let Ok('q') = stdout.read_char() {
            break;
        }
    }
}

async fn process_message(
    connection_port: Arc<SmartHandle>,
    detector: Option<&Detector>,
) -> Result<(), DetectionError> {
    let msg_header = mem::size_of::<FILTER_MESSAGE_HEADER>();

    // In a loop, read data from the socket and write the data back.
    let mut buff: [u8; 0x1000] = unsafe { mem::zeroed() };

    let hr = unsafe {
        FilterGetMessage(
            connection_port.get(),
            buff.as_mut_ptr() as *mut FILTER_MESSAGE_HEADER,
            mem::size_of_val(&buff) as u32,
            null_mut(),
        )
    };

    if hr != STATUS_SUCCESS {
        println!("Failed to get message");
        print_hr_result("", hr);
        print_last_error("");
        return Err(DetectionError::SendMsgError("Failed to get message".to_string()));
    }

    let event_buff = &buff[msg_header..];
    let Some(class) = get_event_type(event_buff) else {
        return Err(DetectionError::UnknownEvent);
    };

    // this viewer decodes the four original event types; other classes are reported by number
    match class {
        FileCreateEvent::EVENT_CLASS => {
            let e = FileCreateEvent::deserialize(event_buff);
            println!("{:?}", e);
            if let (Some(e), Some(detector)) = (&e, detector) {
                report_hits(detector, rade_detection::from_file_create(e));
            }
        },
        ProcessCreateEvent::EVENT_CLASS => {
            let e = ProcessCreateEvent::deserialize(event_buff);
            println!("{:?}", e);
            if let (Some(e), Some(detector)) = (&e, detector) {
                report_hits(detector, rade_detection::from_process_create(e));
            }
        },
        ImageLoadEvent::EVENT_CLASS => {
            let e = ImageLoadEvent::deserialize(event_buff);
            println!("{:?}", e);
            if let (Some(e), Some(detector)) = (&e, detector) {
                report_hits(detector, rade_detection::from_image_load(e));
            }
        },
        RegistrySetValueEvent::EVENT_CLASS => {
            let e = RegistrySetValueEvent::deserialize(event_buff);
            println!("{:?}", e);
            if let (Some(e), Some(detector)) = (&e, detector) {
                report_hits(detector, rade_detection::from_registry_set_value(e));
            }
        },
        _ => println!("event class {class} ({} bytes, not decoded)", event_buff.len()),
    }

    Ok(())
}
