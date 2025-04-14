use crate::error::DetectionError;

use std::{
    mem,
    ptr::{null, null_mut},
    sync::Arc,
};

use ansi_term::Colour::Green;
use common::{
    constants::COMM_PORT_NAME,
    event::{
        get_event_type, image_load::ImageLoadEvent, process_create::ProcessCreateEvent,
        registry_set_value::RegistrySetValueEvent, Event, FileCreateEvent,
    },
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
    error_msg::{print_hr_result, print_last_error},
    handle_wrapper::SmartHandle,
};

#[tokio::main]
pub async fn start_detection() {
    let port_name = u16cstr!(COMM_PORT_NAME).as_ptr();
    let Some(connection_port) = init_port(port_name) else {
        return;
    };

    let _ = ansi_term::enable_ansi_support();
    println!("{} Client connected to driver", Green.paint("SUCCESS!"));

    message_loop(connection_port);

    //CloseHandle(h_connection_port); ??
}

fn init_port(port_name: *const u16) -> Option<SmartHandle> {
    let mut connection_port = SmartHandle::new();

    let hr = unsafe {
        FilterConnectCommunicationPort(
            port_name,
            0,
            null(),
            0,
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
fn message_loop(connection_port: SmartHandle) {
    let arc_connection_port = Arc::new(connection_port);

    let _t = tokio::spawn(async move {
        loop {
            if let Err(e) = process_message(arc_connection_port.clone()).await {
                eprintln!("{}", e);
            }
        }
    });

    let stdout = Term::buffered_stdout();
    loop {
        if let Ok(character) = stdout.read_char() {
            match character {
                'q' => break,
                _ => {}
            }
        }
    }
}

async fn process_message(connection_port: Arc<SmartHandle>) -> Result<(), DetectionError> {
    let msg_header = mem::size_of::<FILTER_MESSAGE_HEADER>();

    // In a loop, read data from the socket and write the data back.
    let mut buff: [u8; 0x1000] = unsafe { mem::zeroed() };

    let hr = unsafe {
        FilterGetMessage(
            connection_port.get() as isize,
            buff.as_mut_ptr() as *mut FILTER_MESSAGE_HEADER,
            mem::size_of_val(&buff) as u32,
            null_mut(),
        )
    };

    if hr != STATUS_SUCCESS {
        println!("Failed to get message");
        print_hr_result("", hr);
        print_last_error("");
        return Err(DetectionError::SendMsgError(
            "Failed to get message".to_string(),
        ));
    }

    let event_buff = &buff[msg_header..];
    let e = get_event_type(event_buff);

    match e {
        FileCreateEvent::EVENT_CLASS => {
            let e = FileCreateEvent::deserialize(event_buff);
            println!("{:?}", e);
        }
        ProcessCreateEvent::EVENT_CLASS => {
            let e = ProcessCreateEvent::deserialize(event_buff);
            println!("{:?}", e);
        }
        ImageLoadEvent::EVENT_CLASS => {
            let e = ImageLoadEvent::deserialize(event_buff);
            println!("{:?}", e);
        }
        RegistrySetValueEvent::EVENT_CLASS => {
            let e = RegistrySetValueEvent::deserialize(event_buff);
            println!("{:?}", e);
        }
        _ => {
            return Err(DetectionError::UnknownEvent);
        }
    }

    Ok(())
}
