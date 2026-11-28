//! Windows-only helper for keyroost's **non-admin FIDO2 tab**.
//!
//! keyroost talks raw CTAP-HID to a security key, which on Windows requires the
//! process to be elevated (admin) since Win10 1903. When keyroost is not
//! elevated it can't manage the key directly — but it can still:
//!
//!   1. **Detect** that a FIDO key is present, without admin and without opening
//!      the protected FIDO interface, via the HID usage page `0xF1D0`
//!      ([`detect_fido_keys`] / [`fido_key_present`]); and
//!   2. **Hand off to Windows** — open the built-in Settings > Accounts >
//!      Sign-in options > Security Key page, which performs PIN / reset /
//!      biometrics **without admin** because Settings itself is the privileged
//!      component ([`open_windows_security_key_settings`]).
//!
//! That is the entire scope: an informational tab plus a link to the Windows
//! security-key page. No passkey enumeration, no PIN/reset over the API (the
//! `webauthn.dll` API was investigated and proved to not support external-key
//! management — see the crate README).
//!
//! On non-Windows targets every function is inert, so the rest of keyroost can
//! depend on this crate unconditionally and branch at runtime.
//!
//! # Verification status
//!
//! The Windows code can't be compiled or run off-Windows. It is written against
//! Microsoft's documented APIs; spots needing on-Windows checking are marked
//! `VERIFY:` in `src/sys.rs`. The non-Windows (inert) path compiles cleanly.

use std::fmt;

/// A FIDO authenticator detected on the system, recognised WITHOUT opening the
/// (admin-gated) FIDO interface. Detection uses only readable HID metadata.
#[derive(Clone, Debug, Default)]
pub struct FidoKeyInfo {
    /// Product / device string, if the OS exposed one (e.g. "TOKEN2 FIDO2 ...").
    pub product: Option<String>,
    /// USB vendor id, if known.
    pub vendor_id: Option<u16>,
    /// USB product id, if known.
    pub product_id: Option<u16>,
}

#[non_exhaustive]
#[derive(Debug, Clone)]
pub enum WinWebAuthnError {
    /// Not running on Windows.
    Unsupported,
    /// Could not launch the Windows settings page.
    LaunchFailed,
    /// Elevated relaunch failed or the UAC prompt was declined.
    RelaunchFailed,
}

impl fmt::Display for WinWebAuthnError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WinWebAuthnError::Unsupported => {
                write!(f, "only available on Windows")
            }
            WinWebAuthnError::LaunchFailed => {
                write!(f, "could not open Windows security-key settings")
            }
            WinWebAuthnError::RelaunchFailed => {
                write!(f, "could not relaunch as administrator")
            }
        }
    }
}

impl std::error::Error for WinWebAuthnError {}

pub type Result<T> = std::result::Result<T, WinWebAuthnError>;

/// Detect FIDO security keys present on the system, WITHOUT administrator rights
/// and without opening the protected FIDO interface.
///
/// Enumerates HID devices and keeps those advertising the FIDO usage page
/// (`0xF1D0`). Returns an empty vec if none are found, or on non-Windows.
pub fn detect_fido_keys() -> Vec<FidoKeyInfo> {
    #[cfg(windows)]
    {
        sys::detect_fido_keys()
    }
    #[cfg(not(windows))]
    {
        Vec::new()
    }
}

/// Convenience: is at least one FIDO key present? Always false on non-Windows.
pub fn fido_key_present() -> bool {
    !detect_fido_keys().is_empty()
}

/// Diagnostic detection: returns (found_keys, human-readable log lines) so a
/// probe can show every HID device seen and why it did or didn't match. Empty
/// log on non-Windows.
pub fn detect_fido_keys_verbose() -> (Vec<FidoKeyInfo>, Vec<String>) {
    #[cfg(windows)]
    {
        sys::detect_fido_keys_verbose()
    }
    #[cfg(not(windows))]
    {
        (Vec::new(), Vec::new())
    }
}

/// Open the Windows built-in security-key management page (Settings > Accounts >
/// Sign-in options > Security Key), which can set/change the PIN, manage
/// biometrics, and reset the key — all WITHOUT administrator rights, because
/// Settings itself is the privileged component.
///
/// Launches `ms-settings:signinoptions-launchsecuritykeyenrollment`, falling
/// back to the general `ms-settings:signinoptions` page if that specific URI is
/// unavailable on this Windows build.
pub fn open_windows_security_key_settings() -> Result<()> {
    #[cfg(windows)]
    {
        sys::open_windows_security_key_settings()
    }
    #[cfg(not(windows))]
    {
        Err(WinWebAuthnError::Unsupported)
    }
}

/// Relaunch the current executable elevated, via a UAC prompt (ShellExecuteW
/// with the "runas" verb). On success the elevated process has been requested
/// and the caller should exit the current, non-elevated one so only one
/// instance runs. Returns `Err` if the user declines the UAC prompt or the
/// launch fails. Always `Unsupported` off-Windows.
pub fn relaunch_as_admin() -> Result<()> {
    #[cfg(windows)]
    {
        sys::relaunch_as_admin()
    }
    #[cfg(not(windows))]
    {
        Err(WinWebAuthnError::Unsupported)
    }
}

/// Parse the UTF-16 `DevicePath` out of a `SP_DEVICE_INTERFACE_DETAIL_DATA_W`
/// byte buffer as returned by `SetupDiGetDeviceInterfaceDetailW`.
///
/// The Win32 struct is `{ DWORD cbSize; WCHAR DevicePath[ANYSIZE_ARRAY]; }`,
/// so the path begins at byte offset 4 and is a NUL-terminated UTF-16LE
/// string. `buf` (a `Vec<u8>`) carries only byte alignment and its
/// terminator is device/SetupApi-controlled, so every 16-bit unit is read
/// with `u16::from_le_bytes` (no `*const u16` deref) and the scan is bounded
/// by `buf.len()` — a buffer missing its terminator cannot drive an
/// out-of-bounds read (KEY-020). Windows is little-endian, matching
/// `from_le_bytes`.
///
/// The only production caller is the `#[cfg(windows)]` `sys` module; on other
/// hosts the function exists solely so the unit tests below exercise it.
// `pub` + `#[doc(hidden)]` so the workspace fuzz harness can reach this
// extent-bounded parser (KEY-020 surface) without it becoming public API.
// (Now that it's public with a Linux fuzz consumer, the prior
// not(windows) dead-code allow is no longer needed.)
#[doc(hidden)]
pub fn parse_detail_path(buf: &[u8]) -> String {
    const PATH_OFFSET: usize = 4;
    let mut units = Vec::new();
    let mut i = PATH_OFFSET;
    while i + 2 <= buf.len() {
        let unit = u16::from_le_bytes([buf[i], buf[i + 1]]);
        if unit == 0 {
            break;
        }
        units.push(unit);
        i += 2;
    }
    String::from_utf16_lossy(&units)
}

/// Stdout's console with VT processing on, so escape sequences (moving the
/// cursor, erasing a line) act instead of printing as text, as they do in
/// the classic console (conhost) by default. Dropping it puts the console
/// mode back as it was. Windows only.
#[cfg(windows)]
pub struct ConsoleVt {
    prev: u32,
}

#[cfg(windows)]
impl Drop for ConsoleVt {
    fn drop(&mut self) {
        sys::console_mode_restore(self.prev);
    }
}

/// Turn on VT processing for stdout's console until the [`ConsoleVt`] is
/// dropped; `None` when stdout is no console or the console can't (the
/// legacy console), so escape sequences would print as text.
#[cfg(windows)]
pub fn console_vt() -> Option<ConsoleVt> {
    sys::console_vt_on().map(|prev| ConsoleVt { prev })
}

#[cfg(windows)]
mod sys;

#[cfg(test)]
mod tests {
    use super::parse_detail_path;

    /// Build a SP_DEVICE_INTERFACE_DETAIL_DATA_W-shaped byte buffer:
    /// 4-byte cbSize, then UTF-16LE `path`, then (optionally) a NUL unit.
    fn detail(path: &str, terminated: bool) -> Vec<u8> {
        let mut b = vec![0x08, 0x00, 0x00, 0x00]; // cbSize placeholder
        for u in path.encode_utf16() {
            b.extend_from_slice(&u.to_le_bytes());
        }
        if terminated {
            b.extend_from_slice(&[0x00, 0x00]);
        }
        b
    }

    #[test]
    fn parses_a_normal_terminated_path() {
        let p = r"\\?\hid#vid_349e&pid_0026&mi_01#7&abc{guid}";
        assert_eq!(parse_detail_path(&detail(p, true)), p);
    }

    #[test]
    fn parsing_is_independent_of_slice_alignment() {
        // A Vec<u8> offset by one byte yields an odd-addressed slice; the
        // parser must not depend on u16 alignment.
        let p = r"\\?\hid#vid_1050&pid_0407#x";
        let mut padded = vec![0xAAu8];
        padded.extend_from_slice(&detail(p, true));
        assert_eq!(parse_detail_path(&padded[1..]), p);
    }

    #[test]
    fn stops_at_buffer_end_when_terminator_is_missing() {
        // The KEY-020 regression: no NUL in the buffer must NOT over-read;
        // the scan is bounded by buf.len() and returns what it has.
        let p = "abcdef";
        assert_eq!(parse_detail_path(&detail(p, false)), p);
    }

    #[test]
    fn tolerates_a_trailing_odd_byte() {
        // A dangling high byte (len not a whole number of u16 units past the
        // offset) must not panic; the incomplete unit is dropped.
        let mut b = detail("hi", false);
        b.push(0x41); // lone trailing byte
        assert_eq!(parse_detail_path(&b), "hi");
    }

    #[test]
    fn handles_a_long_path() {
        let p = format!(r"\\?\hid#{}#col01", "a".repeat(600));
        assert_eq!(parse_detail_path(&detail(&p, true)), p);
    }

    #[test]
    fn empty_or_too_short_buffer_is_empty_string() {
        assert_eq!(parse_detail_path(&[]), "");
        assert_eq!(parse_detail_path(&[0x08, 0x00, 0x00]), ""); // < offset+2
    }
}
