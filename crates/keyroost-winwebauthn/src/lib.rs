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

#[cfg(windows)]
mod sys;
