//! Windows-only still screen capture for keyroost's QR-from-screen feature.
//!
//! A single GDI `BitBlt` of the virtual screen (all monitors) into a top-down
//! 32-bit DIB, returned as RGBA. This crate exists purely to isolate the
//! `unsafe` Win32 FFI from the GUI crate, which forbids unsafe code; Linux and
//! macOS capture live on the safe path in `keyroost`. On non-Windows targets
//! every entry point is inert.

/// A captured frame: `width * height * 4` bytes of RGBA8, top-down.
pub struct Frame {
    pub width: u32,
    pub height: u32,
    pub rgba: Vec<u8>,
}

/// Byte length of a `w × h` RGBA8 frame (`w * h * 4`), or an error if it
/// overflows `usize`. Pulled out of `capture_virtual_screen` so this guard
/// is exercised off-Windows: on a 32-bit target `usize` is 32-bit and a
/// large multi-monitor desktop can wrap the product, which would undersize
/// the buffer `GetDIBits` writes into (a heap overflow). This crate is
/// published to crates.io, where a consumer's release profile may not
/// enable overflow-checks, so the check is explicit rather than relying on
/// them. Inputs are the already-validated non-negative dimensions cast to
/// `usize`.
// Off-Windows the only caller is the cfg(windows) capture path, so the fn is
// otherwise "dead" there — but it must stay compiled on every target so the
// host test suite exercises the overflow branch.
#[cfg_attr(not(windows), allow(dead_code))]
fn rgba_buf_len_checked(w: usize, h: usize) -> Result<usize, String> {
    w.checked_mul(h)
        .and_then(|n| n.checked_mul(4))
        .ok_or_else(|| "virtual screen dimensions too large to capture".into())
}

/// Capture the whole virtual screen (all monitors). Returns an error string
/// describing why capture failed; on non-Windows targets it is always an error.
#[cfg(windows)]
pub fn capture_virtual_screen() -> Result<Frame, String> {
    use windows_sys::Win32::Graphics::Gdi::{
        BitBlt, CreateCompatibleBitmap, CreateCompatibleDC, DeleteDC, DeleteObject, GetDC,
        GetDIBits, ReleaseDC, SelectObject, BITMAPINFO, BITMAPINFOHEADER, BI_RGB, DIB_RGB_COLORS,
        SRCCOPY,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        GetSystemMetrics, SM_CXVIRTUALSCREEN, SM_CYVIRTUALSCREEN, SM_XVIRTUALSCREEN,
        SM_YVIRTUALSCREEN,
    };

    unsafe {
        let x = GetSystemMetrics(SM_XVIRTUALSCREEN);
        let y = GetSystemMetrics(SM_YVIRTUALSCREEN);
        let w = GetSystemMetrics(SM_CXVIRTUALSCREEN);
        let h = GetSystemMetrics(SM_CYVIRTUALSCREEN);
        if w <= 0 || h <= 0 {
            return Err("no virtual screen to capture".into());
        }

        // Size the RGBA readback buffer up front with checked arithmetic, before
        // allocating any GDI objects. On a 32-bit build `usize` is 32-bit, so a
        // very large multi-monitor virtual desktop could overflow `w * h * 4`;
        // GetDIBits writes `w * h * 4` bytes based on the header dimensions, so
        // an undersized buffer from a wrapped length would be a heap overflow.
        // (This crate is published to crates.io, where a consumer's release
        // profile may not enable overflow-checks — so don't rely on those.)
        let buf_len = rgba_buf_len_checked(w as usize, h as usize)?;

        let screen = GetDC(std::ptr::null_mut());
        if screen.is_null() {
            return Err("GetDC(screen) failed".into());
        }
        let mem = CreateCompatibleDC(screen);
        let bmp = CreateCompatibleBitmap(screen, w, h);
        if mem.is_null() || bmp.is_null() {
            if !bmp.is_null() {
                DeleteObject(bmp as _);
            }
            if !mem.is_null() {
                DeleteDC(mem);
            }
            ReleaseDC(std::ptr::null_mut(), screen);
            return Err("could not allocate a capture buffer".into());
        }
        // SelectObject returns the previously selected object, or NULL on
        // failure. A memory DC always has a default 1x1 bitmap selected, so a
        // null here means the call failed and the bitmap isn't selected — the
        // blit/readback would produce garbage, so clean up and bail.
        let prev = SelectObject(mem, bmp as _);
        if prev.is_null() {
            DeleteObject(bmp as _);
            DeleteDC(mem);
            ReleaseDC(std::ptr::null_mut(), screen);
            return Err("SelectObject(capture bitmap) failed".into());
        }

        let blit_ok = BitBlt(mem, 0, 0, w, h, screen, x, y, SRCCOPY) != 0;

        // Deselect the bitmap from the DC *before* GetDIBits: MSDN requires the
        // bitmap not be selected into any DC when GetDIBits reads it. The blit
        // is already done, so nothing else needs the selection.
        SelectObject(mem, prev);

        // Top-down (negative height) 32-bpp BGRA readback.
        let mut info: BITMAPINFO = core::mem::zeroed();
        info.bmiHeader = BITMAPINFOHEADER {
            biSize: core::mem::size_of::<BITMAPINFOHEADER>() as u32,
            biWidth: w,
            biHeight: -h,
            biPlanes: 1,
            biBitCount: 32,
            biCompression: BI_RGB,
            ..core::mem::zeroed()
        };
        let mut buf = vec![0u8; buf_len];
        let lines = GetDIBits(
            mem,
            bmp,
            0,
            h as u32,
            buf.as_mut_ptr().cast(),
            &mut info,
            DIB_RGB_COLORS,
        );

        // Release the remaining GDI objects regardless of outcome.
        DeleteObject(bmp as _);
        DeleteDC(mem);
        ReleaseDC(std::ptr::null_mut(), screen);

        if !blit_ok {
            return Err("BitBlt failed".into());
        }
        // A partial readback (fewer scanlines than requested) leaves black rows,
        // so require the full height, not merely a nonzero count.
        if lines != h {
            return Err("GetDIBits returned an incomplete image".into());
        }

        // BGRA -> RGBA (and force opaque alpha).
        for px in buf.as_chunks_mut::<4>().0 {
            px.swap(0, 2);
            px[3] = 255;
        }
        Ok(Frame {
            width: w as u32,
            height: h as u32,
            rgba: buf,
        })
    }
}

/// Inert on non-Windows targets — keyroost captures those platforms itself.
#[cfg(not(windows))]
pub fn capture_virtual_screen() -> Result<Frame, String> {
    Err("the GDI screen-capture backend is Windows-only".into())
}

#[cfg(test)]
mod tests {
    use super::rgba_buf_len_checked;

    #[test]
    fn computes_a_normal_frame_length() {
        assert_eq!(rgba_buf_len_checked(1920, 1080), Ok(1920 * 1080 * 4));
    }

    #[test]
    fn zero_area_is_zero() {
        assert_eq!(rgba_buf_len_checked(0, 0), Ok(0));
    }

    #[test]
    fn overflow_is_an_error_not_a_wrap() {
        // Guards 32-bit `usize` consumers: w*h*4 that exceeds usize::MAX
        // must return Err, never a wrapped (undersized) length that would
        // let GetDIBits overrun the readback buffer.
        assert!(rgba_buf_len_checked(usize::MAX / 2, 3).is_err());
        assert!(rgba_buf_len_checked(usize::MAX, 1).is_err());
    }
}
