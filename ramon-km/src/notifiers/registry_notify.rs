use core::ptr::null_mut;

use common::{
    event::{registry_set_value::RegistrySetValueEvent, Event},
    utils::try_filled,
};
use kernel_macros::{HandleToU32, NT_SUCCESS};
use kernel_string::PUNICODE_STRING;
use km_api_sys::{
    ntddk::{PsGetCurrentProcessId, PsGetCurrentThreadId, REG_NT_POST_SET_VALUE_KEY},
    wmd::{
        CmCallbackGetKeyObjectIDEx, CmCallbackReleaseKeyObjectIDEx,
        PREG_POST_OPERATION_INFORMATION, PREG_SET_VALUE_KEY_INFORMATION,
    },
};
use winapi::shared::{
    ntdef::{NTSTATUS, PVOID},
    ntstatus::{STATUS_SUCCESS, STATUS_UNSUCCESSFUL},
};

use crate::{send_message::send_message, G_COOKIE};

// not declared in km-api-sys
extern "system" {
    pub(crate) fn MmCopyMemory(
        target: PVOID,
        source: PVOID,
        size: usize,
        flags: u32,
        copied: *mut usize,
    ) -> NTSTATUS;
}
pub(crate) const MM_COPY_MEMORY_VIRTUAL: u32 = 0x2;

pub extern "system" fn OnRegistryNotify(_context: PVOID, arg1: PVOID, arg2: PVOID) -> NTSTATUS {
    let reg_notify = HandleToU32!(arg1);
    if reg_notify == REG_NT_POST_SET_VALUE_KEY {
        log::info!("OnRegistryNotify");
        unsafe {
            let op_info = &*(arg2 as PREG_POST_OPERATION_INFORMATION);
            if !NT_SUCCESS!(op_info.Status) {
                return STATUS_SUCCESS;
            }

            // copy the cookie out of the lock: the call below does not need the lock held
            let cookie = *G_COOKIE.lock();
            let mut name: PUNICODE_STRING = null_mut();
            let status =
                CmCallbackGetKeyObjectIDEx(&cookie, op_info.Object, null_mut(), &mut name, 0);
            if !NT_SUCCESS!(status) {
                return STATUS_SUCCESS;
            }

            if name.is_null() {
                //something wrong
                return STATUS_UNSUCCESSFUL;
            }

            'notify: {
                let key_name = if let Some(key_name) = (*name).as_rust_string() {
                    key_name
                } else {
                    log::info!("Something wrong. Can't convert \"key_name\" to rust string");
                    break 'notify;
                };
                let registry_machine = "\\REGISTRY\\MACHINE";

                // filter out none-HKLM writes
                if key_name.contains(registry_machine) {
                    if op_info.PreInformation.is_null() {
                        //something wrong
                        break 'notify;
                    }

                    let pre_info = &*(op_info.PreInformation as PREG_SET_VALUE_KEY_INFORMATION);
                    let value_name =
                        if let Some(value_name) = (*pre_info.ValueName).as_rust_string() {
                            value_name
                        } else {
                            //log::info!("Something wrong. Can't convert \"value_name\" to rust string");
                            break 'notify;
                        };

                    if pre_info.Data.is_null() {
                        break 'notify;
                    }

                    // Data may be a user buffer that another thread frees: MmCopyMemory fails instead of faulting
                    let size = pre_info.DataSize.min(0x400) as usize;
                    let Ok(mut data) = try_filled(size, 0u8) else {
                        break 'notify;
                    };
                    let mut copied = 0;
                    if size != 0
                        && (!NT_SUCCESS!(MmCopyMemory(
                            data.as_mut_ptr() as PVOID,
                            pre_info.Data,
                            size,
                            MM_COPY_MEMORY_VIRTUAL,
                            &mut copied,
                        )) || copied != size)
                    {
                        break 'notify;
                    }
                    let event = RegistrySetValueEvent::new(
                        HandleToU32!(PsGetCurrentProcessId()),
                        HandleToU32!(PsGetCurrentThreadId()),
                        key_name,
                        value_name,
                        pre_info.DataType,
                        data,
                    );
                    send_message(event.serialize().unwrap_or_default());

                    // let item = RegistrySetValue {
                    //     pid: HandleToU32!(PsGetCurrentProcessId()),
                    //     tid: HandleToU32!(PsGetCurrentThreadId()),
                    //     key_name: ItemInfo::string_to_buffer(key_name),
                    //     value_name,
                    //     data_type: pre_info.DataType,
                    //     data: v.clone(),
                    // };
                }
                break 'notify;
            }
            CmCallbackReleaseKeyObjectIDEx(name);
        }
    }

    STATUS_SUCCESS
}
