//! Windows implementation: HID enumeration to detect a FIDO key (usage page
//! 0xF1D0) and a shell launch of the Windows security-key settings page.
//!
//! All FFI is confined here. VERIFY markers call out spots to check against your
//! exact Windows SDK / hardware.

#![allow(non_snake_case)]

use windows_sys::Win32::Devices::DeviceAndDriverInstallation::{
    SetupDiDestroyDeviceInfoList, SetupDiEnumDeviceInterfaces, SetupDiGetClassDevsW,
    SetupDiGetDeviceInterfaceDetailW, DIGCF_DEVICEINTERFACE, DIGCF_PRESENT, HDEVINFO,
    SP_DEVICE_INTERFACE_DATA,
};
use windows_sys::Win32::Devices::HumanInterfaceDevice::{
    HidD_FreePreparsedData, HidD_GetAttributes, HidD_GetHidGuid, HidD_GetPreparsedData,
    HidD_GetProductString, HidP_GetCaps, HIDD_ATTRIBUTES, HIDP_CAPS, PHIDP_PREPARSED_DATA,
};
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_OVERLAPPED, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};

use crate::{FidoKeyInfo, Result, WinWebAuthnError};

/// The FIDO HID usage page (FIDO Alliance). Authoritative marker of a FIDO key.
const FIDO_USAGE_PAGE: u16 = 0xF1D0;
/// HIDP_STATUS_SUCCESS.
const HIDP_STATUS_SUCCESS: i32 = 0x0011_0000u32 as i32;

/// Encode a Rust &str as a NUL-terminated UTF-16 buffer.
fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Parse `vid_XXXX` / `pid_XXXX` (hex) out of a lowercased HID device path.
fn parse_vid_pid(path_lc: &str) -> (Option<u16>, Option<u16>) {
    fn grab(s: &str, key: &str) -> Option<u16> {
        let i = s.find(key)? + key.len();
        let hex: String = s[i..].chars().take(4).collect();
        u16::from_str_radix(&hex, 16).ok()
    }
    (grab(path_lc, "vid_"), grab(path_lc, "pid_"))
}

/// Push a key, merging duplicates by (vid, pid) so the same physical key seen on
/// multiple HID collections appears once. Prefers an entry that has a product
/// string.
fn push_unique(out: &mut Vec<FidoKeyInfo>, k: FidoKeyInfo) {
    if let Some(existing) = out
        .iter_mut()
        .find(|e| e.vendor_id == k.vendor_id && e.product_id == k.product_id)
    {
        if existing.product.is_none() && k.product.is_some() {
            existing.product = k.product;
        }
        return;
    }
    out.push(k);
}

pub(crate) fn detect_fido_keys() -> Vec<FidoKeyInfo> {
    detect_fido_keys_impl(false).0
}

/// Verbose detection: returns (found_keys, diagnostic_lines).
pub(crate) fn detect_fido_keys_verbose() -> (Vec<FidoKeyInfo>, Vec<String>) {
    detect_fido_keys_impl(true)
}

fn detect_fido_keys_impl(verbose: bool) -> (Vec<FidoKeyInfo>, Vec<String>) {
    let mut out = Vec::new();
    let mut log: Vec<String> = Vec::new();
    macro_rules! dbg {
        ($($a:tt)*) => { if verbose { log.push(format!($($a)*)); } };
    }
    unsafe {
        let mut hid_guid = std::mem::zeroed();
        HidD_GetHidGuid(&mut hid_guid);

        let dev_info: HDEVINFO = SetupDiGetClassDevsW(
            &hid_guid,
            std::ptr::null(),
            std::ptr::null_mut(),
            DIGCF_PRESENT | DIGCF_DEVICEINTERFACE,
        );
        if dev_info == INVALID_HANDLE_VALUE as isize {
            dbg!("SetupDiGetClassDevsW returned INVALID_HANDLE_VALUE");
            return (out, log);
        }

        let mut index = 0u32;
        let mut enumerated = 0u32;
        let mut opened = 0u32;
        loop {
            let mut iface: SP_DEVICE_INTERFACE_DATA = std::mem::zeroed();
            iface.cbSize = std::mem::size_of::<SP_DEVICE_INTERFACE_DATA>() as u32;
            if SetupDiEnumDeviceInterfaces(
                dev_info,
                std::ptr::null_mut(),
                &hid_guid,
                index,
                &mut iface,
            ) == 0
            {
                break; // no more interfaces
            }
            index += 1;
            enumerated += 1;

            // First call: required size for the detail (device-path) struct.
            let mut needed = 0u32;
            SetupDiGetDeviceInterfaceDetailW(
                dev_info,
                &iface,
                std::ptr::null_mut(),
                0,
                &mut needed,
                std::ptr::null_mut(),
            );
            if needed == 0 {
                dbg!("dev {}: detail size query returned 0", index);
                continue;
            }
            // SP_DEVICE_INTERFACE_DETAIL_DATA_W: DWORD cbSize; WCHAR DevicePath[].
            // cbSize is 8 on 64-bit, 6 on 32-bit. Path starts at offset 4.
            let mut buf = vec![0u8; needed as usize];
            let cb_size: u32 = if cfg!(target_pointer_width = "64") { 8 } else { 6 };
            *(buf.as_mut_ptr() as *mut u32) = cb_size;
            if SetupDiGetDeviceInterfaceDetailW(
                dev_info,
                &iface,
                buf.as_mut_ptr() as *mut _,
                needed,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            ) == 0
            {
                dbg!("dev {}: SetupDiGetDeviceInterfaceDetailW failed", index);
                continue;
            }
            let path_ptr = buf.as_ptr().add(4) as *const u16;
            // Read the path into a Rust string (no device open needed). The HID
            // path looks like: \\?\hid#vid_349e&pid_0026&mi_01&col01#...{guid}
            let path = {
                let mut len = 0usize;
                while *path_ptr.add(len) != 0 {
                    len += 1;
                }
                let slice = std::slice::from_raw_parts(path_ptr, len);
                String::from_utf16_lossy(slice)
            };
            let path_lc = path.to_ascii_lowercase();
            let (path_vid, path_pid) = parse_vid_pid(&path_lc);

            // Open device for HID metadata. Zero-access first (works on most
            // collections), then R/W.
            let mut handle = CreateFileW(
                path_ptr,
                0,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                std::ptr::null(),
                OPEN_EXISTING,
                0,
                std::ptr::null_mut(),
            );
            if handle.is_null() || handle as isize == INVALID_HANDLE_VALUE as isize {
                handle = CreateFileW(
                    path_ptr,
                    GENERIC_READ | GENERIC_WRITE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    std::ptr::null(),
                    OPEN_EXISTING,
                    FILE_FLAG_OVERLAPPED,
                    std::ptr::null_mut(),
                );
            }
            if handle.is_null() || handle as isize == INVALID_HANDLE_VALUE as isize {
                let err = GetLastError();
                // ERROR_ACCESS_DENIED (5) on a HID interface is the signature of
                // a Windows-protected FIDO collection: we cannot open it
                // non-elevated, which is exactly the FIDO-HID gating. Treat it as
                // a detected FIDO key, using VID/PID parsed from the path.
                dbg!(
                    "dev {}: CreateFileW failed (err {}) path-VID:{:04X} PID:{:04X}{}",
                    index,
                    err,
                    path_vid.unwrap_or(0),
                    path_pid.unwrap_or(0),
                    if err == 5 { "  <-- protected (FIDO?)" } else { "" }
                );
                if err == 5 {
                    push_unique(
                        &mut out,
                        FidoKeyInfo {
                            product: None,
                            vendor_id: path_vid,
                            product_id: path_pid,
                        },
                    );
                }
                continue;
            }
            opened += 1;

            // VID/PID via HidD_GetAttributes (works on zero-access handle).
            let mut attrs: HIDD_ATTRIBUTES = std::mem::zeroed();
            attrs.Size = std::mem::size_of::<HIDD_ATTRIBUTES>() as u32;
            let (vid, pid) = if HidD_GetAttributes(handle, &mut attrs) != 0 {
                (Some(attrs.VendorID), Some(attrs.ProductID))
            } else {
                (path_vid, path_pid)
            };

            // Usage page via preparsed data + caps.
            let mut preparsed: PHIDP_PREPARSED_DATA = 0;
            let mut usage_page = 0u16;
            if HidD_GetPreparsedData(handle, &mut preparsed) != 0 && preparsed != 0 {
                let mut caps: HIDP_CAPS = std::mem::zeroed();
                if HidP_GetCaps(preparsed, &mut caps) == HIDP_STATUS_SUCCESS {
                    usage_page = caps.UsagePage;
                }
                HidD_FreePreparsedData(preparsed);
            }

            dbg!(
                "dev {}: VID:{:04X} PID:{:04X} usage_page:0x{:04X}{}",
                index,
                vid.unwrap_or(0),
                pid.unwrap_or(0),
                usage_page,
                if usage_page == FIDO_USAGE_PAGE { "  <-- FIDO" } else { "" }
            );

            if usage_page == FIDO_USAGE_PAGE {
                let mut product = None;
                let mut prod_buf = [0u16; 128];
                if HidD_GetProductString(
                    handle,
                    prod_buf.as_mut_ptr() as *mut _,
                    (prod_buf.len() * 2) as u32,
                ) != 0
                {
                    if let Some(end) = prod_buf.iter().position(|&c| c == 0) {
                        let s = String::from_utf16_lossy(&prod_buf[..end]);
                        if !s.is_empty() {
                            product = Some(s);
                        }
                    }
                }
                push_unique(
                    &mut out,
                    FidoKeyInfo {
                        product,
                        vendor_id: vid,
                        product_id: pid,
                    },
                );
            }

            CloseHandle(handle);
        }

        dbg!(
            "enumerated {} HID interface(s), opened {}, found {} FIDO",
            enumerated,
            opened,
            out.len()
        );
        SetupDiDestroyDeviceInfoList(dev_info);
    }
    (out, log)
}

#[allow(dead_code)]
fn _unused() {}

pub(crate) fn open_windows_security_key_settings() -> Result<()> {
    use windows_sys::Win32::UI::Shell::ShellExecuteW;
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

    // Preferred deep link to the security-key page, then a general fallback if
    // that URI isn't recognised on this Windows build.
    const PRIMARY: &str = "ms-settings:signinoptions-launchsecuritykeyenrollment";
    const FALLBACK: &str = "ms-settings:signinoptions";

    let open = to_wide("open");
    for uri in [PRIMARY, FALLBACK] {
        let uri_w = to_wide(uri);
        let h = unsafe {
            ShellExecuteW(
                std::ptr::null_mut(),
                open.as_ptr(),
                uri_w.as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                SW_SHOWNORMAL,
            )
        };
        // ShellExecuteW returns a value > 32 on success.
        if (h as isize) > 32 {
            return Ok(());
        }
    }
    Err(WinWebAuthnError::LaunchFailed)
}

pub(crate) fn relaunch_as_admin() -> Result<()> {
    use windows_sys::Win32::UI::Shell::ShellExecuteW;
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

    // Resolve the current executable path; ShellExecuteW with the "runas" verb
    // triggers the UAC elevation prompt on it.
    let exe = std::env::current_exe().map_err(|_| WinWebAuthnError::RelaunchFailed)?;
    let exe_w = to_wide(&exe.to_string_lossy());
    let verb = to_wide("runas");

    let h = unsafe {
        ShellExecuteW(
            std::ptr::null_mut(),
            verb.as_ptr(),
            exe_w.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            SW_SHOWNORMAL,
        )
    };
    // > 32 == success. <= 32 includes SE_ERR_ACCESSDENIED / a declined UAC prompt.
    if (h as isize) > 32 {
        Ok(())
    } else {
        Err(WinWebAuthnError::RelaunchFailed)
    }
}
