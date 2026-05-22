//! CTAP HID transport and CTAP2 command layer.
//!
//! Phase 1 of extending MoltoUI toward FIDO2/U2F support. This crate sits
//! above [`molto2_hid`]: HID enumeration finds candidates, this crate opens
//! a CTAP HID channel and issues CTAP2 commands.
//!
//! No external dependencies (per CLAUDE.md's vendor-over-depend rule):
//! - [`cbor`] is a from-scratch canonical-CBOR codec scoped to what CTAP
//!   actually emits and consumes.
//! - [`hid`] frames CTAP HID over a plain `/dev/hidraw*` file handle.
//! - [`cmd`] turns CTAP2 commands into typed Rust calls.
//!
//! Currently Linux-only; cross-platform HID backends are a later phase.

pub mod cbor;
pub mod cmd;
pub mod hid;

pub use cmd::{get_info, reset, AuthenticatorInfo, CtapError};
pub use hid::{CtapHidDevice, InitResponse};
