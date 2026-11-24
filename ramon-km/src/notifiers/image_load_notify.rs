use common::{
    event::{image_load::ImageLoadEvent, Event},
    utils::try_to_string,
};
use kernel_macros::HandleToU32;
use kernel_string::PUNICODE_STRING;
use km_api_sys::ntddk::PIMAGE_INFO;
use winapi::shared::ntdef::HANDLE;

use crate::send_message::send_message;

pub extern "system" fn OnImageLoadNotify(
    full_image_name: PUNICODE_STRING,
    process_id: HANDLE,
    image_info: PIMAGE_INFO,
) {
    if process_id.is_null() {
        // system image, ignore
        return;
    }

    unsafe {
        log::info!("OnImageLoadNotify");

        let image_name = match full_image_name.as_ref().and_then(|name| name.as_rust_string()) {
            Some(name) => name,
            None => match try_to_string("(unknown)") {
                Ok(name) => name,
                Err(_) => return,
            },
        };

        let image_info = &*image_info;
        let event = ImageLoadEvent::new(
            HandleToU32!(process_id),
            image_info.ImageBase as u64,
            image_info.ImageSize as u64,
            image_name,
        );
        send_message(event.serialize().unwrap_or_default());
    }
}
