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
            let cb_size: u32 = if cfg!(target_pointer_width = "64") {
                8
            } else {
                6
            };
            // `buf` is a Vec<u8> (align 1), so write cbSize unaligned rather
            // than through a `*mut u32` deref (which would be UB on a
            // 2/4-misaligned allocation).
            std::ptr::write_unaligned(buf.as_mut_ptr() as *mut u32, cb_size);
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
            // Parse the device path for our own use (matching/logging) with a
            // safe, extent-bounded reader that needs no u16 alignment and
            // cannot over-read a terminator-less buffer (KEY-020).
            let path = crate::parse_detail_path(&buf);
            // Raw pointer to the same NUL-terminated UTF-16 path for the Win32
            // CreateFileW call below. SetupApi guarantees the terminator on
            // success; CreateFileW reads up to it.
            let path_ptr = buf.as_ptr().add(4) as *const u16;
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
                    if err == 5 {
                        "  <-- protected (FIDO?)"
                    } else {
                        ""
                    }
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
            let (vid, pid) = if HidD_GetAttributes(handle, &mut attrs) {
                (Some(attrs.VendorID), Some(attrs.ProductID))
            } else {
                (path_vid, path_pid)
            };

            // Usage page via preparsed data + caps.
            let mut preparsed: PHIDP_PREPARSED_DATA = 0;
            let mut usage_page = 0u16;
            if HidD_GetPreparsedData(handle, &mut preparsed) && preparsed != 0 {
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
                if usage_page == FIDO_USAGE_PAGE {
                    "  <-- FIDO"
                } else {
                    ""
                }
            );

            if usage_page == FIDO_USAGE_PAGE {
                let mut product = None;
                let mut prod_buf = [0u16; 128];
                if HidD_GetProductString(
                    handle,
                    prod_buf.as_mut_ptr() as *mut _,
                    (prod_buf.len() * 2) as u32,
                ) {
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

/// Turn on VT processing for stdout's console; the mode it had before, or
/// `None` when stdout is no console or the console refuses (the legacy
/// console).
pub(crate) fn console_vt_on() -> Option<u32> {
    use windows_sys::Win32::System::Console::{
        GetConsoleMode, GetStdHandle, SetConsoleMode, ENABLE_VIRTUAL_TERMINAL_PROCESSING,
        STD_OUTPUT_HANDLE,
    };
    // SAFETY: GetStdHandle takes no pointers; GetConsoleMode writes one u32
    // through a pointer to a live local; SetConsoleMode takes the handle and
    // a value. A handle that is null, invalid or not a console makes the
    // mode calls fail, which is checked.
    unsafe {
        let h = GetStdHandle(STD_OUTPUT_HANDLE);
        if h.is_null() || h == INVALID_HANDLE_VALUE {
            return None;
        }
        let mut mode = 0u32;
        if GetConsoleMode(h, &mut mode) == 0 {
            return None;
        }
        if mode & ENABLE_VIRTUAL_TERMINAL_PROCESSING != 0
            || SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING) != 0
        {
            Some(mode)
        } else {
            None
        }
    }
}

/// Put back the stdout console mode [`console_vt_on`] found.
pub(crate) fn console_mode_restore(mode: u32) {
    use windows_sys::Win32::System::Console::{GetStdHandle, SetConsoleMode, STD_OUTPUT_HANDLE};
    // SAFETY: as in `console_vt_on`; a failure leaves VT on, which is harmless.
    unsafe {
        let h = GetStdHandle(STD_OUTPUT_HANDLE);
        if !h.is_null() && h != INVALID_HANDLE_VALUE {
            SetConsoleMode(h, mode);
        }
    }
}

// ---------------------------------------------------------------------------
// Ctrl+C while the CLI shows a password: erase it before the process ends.
// ---------------------------------------------------------------------------

use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, AtomicUsize, Ordering};
use windows_sys::Win32::Foundation::HANDLE;

/// The stdout console mode [`console_vt_on`] found, while a [`crate::ConsoleVt`]
/// holds VT on: the Ctrl+C handler puts it back as the guard's drop would.
static VT_PREV: AtomicU32 = AtomicU32::new(0);
static VT_HELD: AtomicBool = AtomicBool::new(false);

/// Record that VT is held over `prev` (called by [`crate::console_vt`]).
pub(crate) fn note_vt_held(prev: u32) {
    VT_PREV.store(prev, Ordering::Release);
    VT_HELD.store(true, Ordering::Release);
}

/// VT is no longer held (called when the [`crate::ConsoleVt`] drops).
pub(crate) fn note_vt_released() {
    VT_HELD.store(false, Ordering::Release);
}

/// What the handler writes, and the console input it puts back. Set while
/// an [`crate::EraseOnInterrupt`] is held; `ARMED` says the rest is valid.
static ARMED: AtomicBool = AtomicBool::new(false);
static ERASE_PTR: AtomicPtr<u8> = AtomicPtr::new(std::ptr::null_mut());
static ERASE_LEN: AtomicUsize = AtomicUsize::new(0);
static NOTE_PTR: AtomicPtr<u8> = AtomicPtr::new(std::ptr::null_mut());
static NOTE_LEN: AtomicUsize = AtomicUsize::new(0);
static CONIN: AtomicPtr<core::ffi::c_void> = AtomicPtr::new(std::ptr::null_mut());
static CONIN_MODE: AtomicU32 = AtomicU32::new(0);

/// Write `ptr`/`len` (a `&'static str` stored above) to the console `h`.
///
/// # Safety
/// `ptr`/`len` come from a `&'static str`, or are null/0.
unsafe fn write_console(h: HANDLE, ptr: *const u8, len: usize) {
    use windows_sys::Win32::System::Console::WriteConsoleA;
    if ptr.is_null() || len == 0 || h.is_null() || h == INVALID_HANDLE_VALUE {
        return;
    }
    let mut written = 0u32;
    // SAFETY: the buffer is a live 'static string of `len` bytes; the
    // count pointer is a live local; a non-console handle makes the call
    // fail, which leaves nothing to do.
    unsafe {
        WriteConsoleA(
            h,
            ptr,
            u32::try_from(len).unwrap_or(u32::MAX),
            &mut written,
            std::ptr::null(),
        );
    }
}

/// Runs on a thread of its own when Ctrl+C or Ctrl+Break reaches the
/// console: writes the erase (stdout) and the note (stderr), puts the
/// console modes back, and returns FALSE so the next handler (by default,
/// the one that ends the process with the usual Ctrl+C status) runs.
unsafe extern "system" fn on_ctrl(ctrl: u32) -> windows_sys::core::BOOL {
    use windows_sys::Win32::System::Console::{
        GetStdHandle, SetConsoleMode, CTRL_BREAK_EVENT, CTRL_C_EVENT, STD_ERROR_HANDLE,
        STD_OUTPUT_HANDLE,
    };
    if (ctrl == CTRL_C_EVENT || ctrl == CTRL_BREAK_EVENT) && ARMED.swap(false, Ordering::AcqRel) {
        // SAFETY: the pointers were stored from 'static strings while armed;
        // the handles are the process's own standard handles and the
        // CONIN$ handle the guard keeps open until after it disarms.
        unsafe {
            let out = GetStdHandle(STD_OUTPUT_HANDLE);
            write_console(
                out,
                ERASE_PTR.load(Ordering::Acquire),
                ERASE_LEN.load(Ordering::Acquire),
            );
            if VT_HELD.load(Ordering::Acquire) && !out.is_null() && out != INVALID_HANDLE_VALUE {
                SetConsoleMode(out, VT_PREV.load(Ordering::Acquire));
            }
            let conin = CONIN.load(Ordering::Acquire);
            if !conin.is_null() && conin != INVALID_HANDLE_VALUE {
                SetConsoleMode(conin, CONIN_MODE.load(Ordering::Acquire));
            }
            write_console(
                GetStdHandle(STD_ERROR_HANDLE),
                NOTE_PTR.load(Ordering::Acquire),
                NOTE_LEN.load(Ordering::Acquire),
            );
        }
    }
    0
}

/// Arm the Ctrl+C handler: `conin` (the console's input, kept open by the
/// caller) has its mode saved for the handler to put back. False when one
/// is already armed or the handler can't be added.
pub(crate) fn ctrl_erase_arm(erase: &'static str, note: &'static str, conin: HANDLE) -> bool {
    use windows_sys::Win32::System::Console::{GetConsoleMode, SetConsoleCtrlHandler};
    if ARMED.load(Ordering::Acquire) {
        return false;
    }
    let mut mode = 0u32;
    // SAFETY: GetConsoleMode writes one u32 through a pointer to a live
    // local; a handle that is no console makes it fail (no mode to restore).
    let have_mode = !conin.is_null() && unsafe { GetConsoleMode(conin, &mut mode) } != 0;
    CONIN.store(
        if have_mode {
            conin
        } else {
            std::ptr::null_mut()
        },
        Ordering::Release,
    );
    CONIN_MODE.store(mode, Ordering::Release);
    ERASE_PTR.store(erase.as_ptr().cast_mut(), Ordering::Release);
    ERASE_LEN.store(erase.len(), Ordering::Release);
    NOTE_PTR.store(note.as_ptr().cast_mut(), Ordering::Release);
    NOTE_LEN.store(note.len(), Ordering::Release);
    ARMED.store(true, Ordering::Release);
    // SAFETY: `on_ctrl` is a plain `extern "system"` function that lives
    // for the whole process.
    if unsafe { SetConsoleCtrlHandler(Some(on_ctrl), 1) } == 0 {
        ARMED.store(false, Ordering::Release);
        return false;
    }
    true
}

/// Disarm and remove the handler [`ctrl_erase_arm`] added.
pub(crate) fn ctrl_erase_disarm() {
    use windows_sys::Win32::System::Console::SetConsoleCtrlHandler;
    ARMED.store(false, Ordering::Release);
    // SAFETY: removes the same function pointer that was added.
    unsafe {
        SetConsoleCtrlHandler(Some(on_ctrl), 0);
    }
    CONIN.store(std::ptr::null_mut(), Ordering::Release);
}
