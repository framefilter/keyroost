//! Windows-only device-tree lookups for keyroost's key pairing (#51).
//!
//! On Windows a security key with both a FIDO HID interface and a smart-card
//! (CCID) interface shows up as two unrelated things: a hidapi path and a
//! PC/SC reader name. Windows reports no USB bus/address for either, so the
//! "same physical USB device" evidence Linux gets from sysfs and the reader's
//! `CHANNEL_ID` is missing. The Windows device tree has it: both interfaces
//! hang under the same USB device devnode.
//!
//! This crate only *reads* that tree. It returns each node's raw ancestor
//! chain of device instance IDs (the node itself first); the decision of which
//! entry is the comparable USB device node lives in `keyroost-hid`
//! (`usb_device_node`), which forbids unsafe code and is unit-tested on every
//! platform. This crate exists purely to isolate the `unsafe` Win32 FFI.
//!
//! Neither lookup opens the HID device or connects to a card:
//! - a HID path is resolved with `CM_Get_Device_Interface_PropertyW`
//!   (`DEVPKEY_Device_InstanceId`), which reads PnP metadata only, so it works
//!   without admin;
//! - a reader name is resolved with `SCardGetReaderDeviceInstanceIdA` on one
//!   short-lived PC/SC context, which does not touch the reader's state, so it
//!   is safe on a Molto2 (which must never be connected to during a scan).
//!
//! It also reads a USB device node's product string from the same metadata
//! ([`usb_product_name`]), for naming a key whose reader name carries no model.
//!
//! Every failure yields `None` ("no evidence"), never an error. On non-Windows
//! targets every entry point is inert.

use std::ffi::CStr;

/// Most levels (the node itself included) a chain records. Pairing needs only
/// the first three; the rest is kept so a `--debug` trace shows the hub above.
pub const MAX_CHAIN_LEN: usize = 8;

/// The ancestor chain of the devnode behind a hidapi HID path (`\\?\HID#…`),
/// node first, as device instance IDs. `None` on any error, and always `None`
/// off Windows. The device is never opened.
#[must_use]
pub fn hid_path_chain(path: &str) -> Option<Vec<String>> {
    #[cfg(windows)]
    {
        sys::hid_path_chain(path)
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        None
    }
}

/// The ancestor chain of each PC/SC reader's devnode, parallel to `readers`
/// (the exact names PC/SC listed). Uses one PC/SC context for the whole batch
/// and never connects to a card. An entry is `None` when that reader's lookup
/// failed (including inside a Remote Desktop session, where the call is not
/// redirected); every entry is `None` off Windows.
#[must_use]
pub fn reader_chains(readers: &[&CStr]) -> Vec<Option<Vec<String>>> {
    #[cfg(windows)]
    {
        sys::reader_chains(readers)
    }
    #[cfg(not(windows))]
    {
        vec![None; readers.len()]
    }
}

/// The USB product string (`iProduct`) the device behind a USB device
/// instance ID reported to Windows, as the device tree keeps it
/// (`DEVPKEY_Device_BusReportedDeviceDesc`). Read from PnP metadata only, so
/// it works without admin, where a FIDO HID interface can't be opened to ask.
/// `None` on any error, and always `None` off Windows.
#[must_use]
pub fn usb_product_name(instance_id: &str) -> Option<String> {
    #[cfg(windows)]
    {
        sys::usb_product_name(instance_id)
    }
    #[cfg(not(windows))]
    {
        let _ = instance_id;
        None
    }
}

#[cfg(windows)]
#[allow(non_snake_case)]
mod sys {
    use std::ffi::CStr;
    use std::ptr;

    use windows_sys::Win32::Devices::DeviceAndDriverInstallation::{
        CM_Get_DevNode_PropertyW, CM_Get_Device_IDW, CM_Get_Device_Interface_PropertyW,
        CM_Get_Parent, CM_Locate_DevNodeW, CM_LOCATE_DEVNODE_NORMAL, CR_SUCCESS, MAX_DEVICE_ID_LEN,
    };
    use windows_sys::Win32::Devices::Properties::{
        DEVPKEY_Device_BusReportedDeviceDesc, DEVPKEY_Device_InstanceId, DEVPROPTYPE,
        DEVPROP_TYPE_STRING,
    };
    use windows_sys::Win32::Security::Credentials::{
        SCardEstablishContext, SCardGetReaderDeviceInstanceIdA, SCardReleaseContext,
        SCARD_SCOPE_USER,
    };

    use super::MAX_CHAIN_LEN;

    /// UTF-16 buffer length (in u16s) for one device instance ID: the
    /// documented maximum plus the terminating NUL, with headroom.
    const ID_BUF_CHARS: usize = MAX_DEVICE_ID_LEN as usize + 8;
    /// Upper bound on a reader's instance-ID length (chars incl. NUL) we accept
    /// from the sizing call, so a bogus size never drives a large allocation.
    const MAX_READER_ID_CHARS: u32 = 1024;

    /// The string up to the first NUL, or `None` if empty or not UTF-16.
    fn wide_to_string(buf: &[u16]) -> Option<String> {
        let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        String::from_utf16(&buf[..end])
            .ok()
            .filter(|s| !s.is_empty())
    }

    /// `s` as a NUL-terminated UTF-16 buffer.
    fn to_wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// The instance ID of `devinst`, or `None` on any error.
    fn device_id(devinst: u32) -> Option<String> {
        let mut buf = vec![0u16; ID_BUF_CHARS];
        // SAFETY: `buf` is a live, writable buffer of `buf.len()` u16s, and that
        // exact length is passed, so the call cannot write past it.
        let cr = unsafe { CM_Get_Device_IDW(devinst, buf.as_mut_ptr(), buf.len() as u32, 0) };
        if cr != CR_SUCCESS {
            return None;
        }
        wide_to_string(&buf)
    }

    /// The devnode handle for instance ID `id`, or `None` if it isn't present.
    fn locate(id: &str) -> Option<u32> {
        let wid = to_wide(id);
        let mut devinst: u32 = 0;
        // SAFETY: `wid` is a NUL-terminated UTF-16 string that outlives the
        // call; `devinst` is a valid out-pointer.
        let cr =
            unsafe { CM_Locate_DevNodeW(&mut devinst, wid.as_ptr(), CM_LOCATE_DEVNODE_NORMAL) };
        (cr == CR_SUCCESS).then_some(devinst)
    }

    /// UTF-16 buffer length (in u16s) for a USB product string: a USB string
    /// descriptor holds at most 126 characters.
    const PRODUCT_BUF_CHARS: usize = 256;

    pub(super) fn usb_product_name(id: &str) -> Option<String> {
        let devinst = locate(id)?;
        let mut buf = vec![0u16; PRODUCT_BUF_CHARS];
        let mut size_bytes: u32 = (buf.len() * 2) as u32;
        let mut ty: DEVPROPTYPE = 0;
        // SAFETY: `devinst` came from CM_Locate_DevNodeW; the property key is
        // a static; `ty` and `size_bytes` are valid out-pointers; `buf` is
        // writable for `size_bytes` bytes (its exact byte length).
        let cr = unsafe {
            CM_Get_DevNode_PropertyW(
                devinst,
                &DEVPKEY_Device_BusReportedDeviceDesc,
                &mut ty,
                buf.as_mut_ptr().cast::<u8>(),
                &mut size_bytes,
                0,
            )
        };
        if cr != CR_SUCCESS || ty != DEVPROP_TYPE_STRING {
            return None;
        }
        let chars = (size_bytes as usize / 2).min(buf.len());
        wide_to_string(&buf[..chars])
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    }

    /// `id` followed by its ancestors' instance IDs, at most
    /// [`MAX_CHAIN_LEN`] entries. Reaching the top of the tree (no parent)
    /// ends the chain; any other failure yields `None`.
    fn chain_from_instance_id(id: &str) -> Option<Vec<String>> {
        let mut cur = locate(id)?;
        let mut chain = vec![id.to_string()];
        while chain.len() < MAX_CHAIN_LEN {
            let mut parent: u32 = 0;
            // SAFETY: `parent` is a valid out-pointer; `cur` is a devnode handle
            // returned by CM_Locate_DevNodeW / CM_Get_Parent.
            let cr = unsafe { CM_Get_Parent(&mut parent, cur, 0) };
            if cr != CR_SUCCESS {
                // The root devnode has no parent: the chain is complete.
                break;
            }
            chain.push(device_id(parent)?);
            cur = parent;
        }
        Some(chain)
    }

    pub(super) fn hid_path_chain(path: &str) -> Option<Vec<String>> {
        let wpath = to_wide(path);
        let mut buf = vec![0u16; ID_BUF_CHARS];
        let mut size_bytes: u32 = (buf.len() * 2) as u32;
        let mut ty: DEVPROPTYPE = 0;
        // SAFETY: `wpath` is NUL-terminated and outlives the call; the property
        // key is a static; `ty` and `size_bytes` are valid out-pointers; `buf`
        // is writable for `size_bytes` bytes (its exact byte length).
        let cr = unsafe {
            CM_Get_Device_Interface_PropertyW(
                wpath.as_ptr(),
                &DEVPKEY_Device_InstanceId,
                &mut ty,
                buf.as_mut_ptr().cast::<u8>(),
                &mut size_bytes,
                0,
            )
        };
        if cr != CR_SUCCESS || ty != DEVPROP_TYPE_STRING {
            return None;
        }
        let chars = (size_bytes as usize / 2).min(buf.len());
        let id = wide_to_string(&buf[..chars])?;
        chain_from_instance_id(&id)
    }

    /// One reader's devnode instance ID, via the two-call sizing protocol.
    fn reader_instance_id(ctx: usize, reader: &CStr) -> Option<String> {
        let mut len: u32 = 0;
        // SAFETY: `reader` is NUL-terminated and outlives the call; a null
        // output buffer asks only for the required length, written to `len`.
        let rv = unsafe {
            SCardGetReaderDeviceInstanceIdA(ctx, reader.as_ptr().cast(), ptr::null_mut(), &mut len)
        };
        if rv != 0 || len == 0 || len > MAX_READER_ID_CHARS {
            return None;
        }
        let mut buf = vec![0u8; len as usize];
        let mut got = len;
        // SAFETY: `buf` is writable for `len` bytes and `got` says so.
        let rv = unsafe {
            SCardGetReaderDeviceInstanceIdA(ctx, reader.as_ptr().cast(), buf.as_mut_ptr(), &mut got)
        };
        if rv != 0 {
            return None;
        }
        let filled = (got as usize).min(buf.len());
        let end = buf[..filled].iter().position(|&b| b == 0).unwrap_or(filled);
        let id = &buf[..end];
        // Device instance IDs are ASCII; anything else is not one.
        if id.is_empty() || !id.is_ascii() {
            return None;
        }
        String::from_utf8(id.to_vec()).ok()
    }

    pub(super) fn reader_chains(readers: &[&CStr]) -> Vec<Option<Vec<String>>> {
        let mut out = vec![None; readers.len()];
        if readers.is_empty() {
            return out;
        }
        let mut ctx: usize = 0;
        // SAFETY: the reserved pointers must be null; `ctx` is a valid
        // out-pointer.
        let rv =
            unsafe { SCardEstablishContext(SCARD_SCOPE_USER, ptr::null(), ptr::null(), &mut ctx) };
        if rv != 0 {
            return out;
        }
        for (slot, reader) in out.iter_mut().zip(readers) {
            *slot = reader_instance_id(ctx, reader).and_then(|id| chain_from_instance_id(&id));
        }
        // SAFETY: `ctx` was established above and is released exactly once.
        unsafe {
            SCardReleaseContext(ctx);
        }
        out
    }
}

#[cfg(all(test, not(windows)))]
mod tests {
    use super::*;

    #[test]
    fn inert_off_windows() {
        assert!(hid_path_chain(r"\\?\HID#VID_349E&PID_0014").is_none());
        let a = c"TOKEN2 FIDO2 Security Key(0014) 0";
        let b = c"TOKEN2 FIDO2 Security Key(0024) 0";
        assert_eq!(reader_chains(&[a, b]), vec![None, None]);
        assert!(reader_chains(&[]).is_empty());
        assert!(usb_product_name(r"USB\VID_1209&PID_BEEE\0123").is_none());
    }
}
