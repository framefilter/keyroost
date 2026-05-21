//! Pure-Rust protocol layer for the Token2 Molto2 / Molto2v2 programmable TOTP token.
//!
//! This crate is hardware-free: it builds APDUs and parses responses. The
//! `molto2-transport` crate wraps it with a real PC/SC connection.

pub mod apdu;
pub mod codec;
pub mod commands;
pub mod sha1;
pub mod sm4;

pub use commands::{
    answer_challenge, derive_sm4_key, factory_reset, get_challenge, get_info, set_config,
    set_customer_key, set_seed, set_title, sw_auth_failed, sw_ok, sync_time, Command,
    DisplayTimeout, HmacAlgo, OtpDigits, ProfileConfig, TimeStep, DEFAULT_CUSTOMER_KEY,
};

/// USB Vendor ID assigned to Token2 Molto2 family.
pub const USB_VID: u16 = 0x349E;
/// USB Product ID for the Molto2 / Molto2v2.
pub const USB_PID: u16 = 0x0300;
/// Substring to match in the PC/SC reader name.
pub const READER_NAME_HINT: &str = "TOKEN2";
