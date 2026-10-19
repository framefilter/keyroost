//! Lightweight, still-only screen capture for QR-from-screen (feature `qr`).
//!
//! Keeps the one-click "scan my screen" UX without dragging in a video-capture
//! stack. Each platform backend produces frames the QR decoder already
//! understands — raw RGBA pixels or PNG bytes — so decoding and otpauth parsing
//! are entirely reused from `keyroost-qr`:
//!
//! * Linux X11     — `x11rb` root-window `GetImage` (already in the tree)
//! * Linux Wayland — xdg-desktop-portal `Screenshot` via `ashpd` (pure Rust)
//! * macOS         — the built-in `/usr/sbin/screencapture` binary
//! * Windows       — GDI `BitBlt` of the virtual screen via the `windows` crate
//!
//! Capture happens locally — nothing is sent anywhere.

/// A captured screen in whatever form the platform backend produced. Both
/// variants feed `keyroost-qr`: raw pixels via `texts_from_rgba`, encoded bytes
/// via `texts_from_image`. Which variant is produced is platform-dependent
/// (macOS only `Png`, Windows only `Rgba`), so allow either to be unused.
#[allow(dead_code)]
pub enum Capture {
    /// Raw RGBA8, `width * height * 4` bytes (X11, Windows).
    Rgba {
        width: u32,
        height: u32,
        data: Vec<u8>,
    },
    /// PNG bytes as written by the platform (Wayland portal, macOS).
    Png(Vec<u8>),
}

/// Grab the screen(s). An `Err` means no backend could run at all; an empty
/// `Vec` means capture ran but produced nothing to scan.
pub fn capture_screens() -> Result<Vec<Capture>, String> {
    #[cfg(target_os = "linux")]
    {
        linux::capture()
    }
    #[cfg(target_os = "macos")]
    {
        macos::capture()
    }
    #[cfg(target_os = "windows")]
    {
        windows_gdi::capture()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        Err("screen capture isn't supported on this platform".into())
    }
}

// ---------------------------------------------------------------------------
// Linux: X11 direct grab, or the Wayland portal on a Wayland session.
// ---------------------------------------------------------------------------
#[cfg(target_os = "linux")]
mod linux {
    use super::Capture;

    pub fn capture() -> Result<Vec<Capture>, String> {
        // On a Wayland session an X11 client (even via XWayland) can't read
        // other clients' pixels, so we must go through the portal. Detect
        // Wayland first and fall back to a direct X11 grab otherwise.
        if is_wayland() {
            wayland_portal().map(|png| vec![Capture::Png(png)])
        } else {
            x11_grab().map(|c| vec![c])
        }
    }

    fn is_wayland() -> bool {
        std::env::var_os("WAYLAND_DISPLAY").is_some()
            || std::env::var("XDG_SESSION_TYPE").is_ok_and(|s| s.eq_ignore_ascii_case("wayland"))
    }

    /// Grab the whole X11 root window via `GetImage`.
    fn x11_grab() -> Result<Capture, String> {
        use x11rb::connection::Connection;
        use x11rb::protocol::xproto::{ConnectionExt, ImageFormat};

        let (conn, screen_num) =
            x11rb::connect(None).map_err(|e| format!("cannot reach the X server: {e}"))?;
        let screen = &conn.setup().roots[screen_num];
        let (root, w, h) = (screen.root, screen.width_in_pixels, screen.height_in_pixels);

        let reply = conn
            .get_image(ImageFormat::Z_PIXMAP, root, 0, 0, w, h, !0)
            .map_err(|e| format!("GetImage request failed: {e}"))?
            .reply()
            .map_err(|e| format!("GetImage failed: {e}"))?;

        let data = zpixmap_to_rgba(&reply.data, w as u32, h as u32)?;
        Ok(Capture::Rgba {
            width: w as u32,
            height: h as u32,
            data,
        })
    }

    /// Convert a Z-Pixmap frame to RGBA. Handles the common 32-bpp (BGRX, no
    /// scanline padding) and 24-bpp (BGR) cases; anything else is refused so the
    /// caller can fall back to file/paste import rather than decode garbage.
    fn zpixmap_to_rgba(src: &[u8], w: u32, h: u32) -> Result<Vec<u8>, String> {
        let px = w as usize * h as usize;
        if px == 0 {
            return Err("X server reported a zero-sized screen".into());
        }
        let bpp = src.len() / px;
        let mut out = vec![0u8; px * 4];
        match bpp {
            4 => {
                for (o, s) in out
                    .as_chunks_mut::<4>()
                    .0
                    .iter_mut()
                    .zip(src.as_chunks::<4>().0)
                {
                    o[0] = s[2]; // R
                    o[1] = s[1]; // G
                    o[2] = s[0]; // B
                    o[3] = 255;
                }
            }
            3 => {
                for (o, s) in out
                    .as_chunks_mut::<4>()
                    .0
                    .iter_mut()
                    .zip(src.as_chunks::<3>().0)
                {
                    o[0] = s[2];
                    o[1] = s[1];
                    o[2] = s[0];
                    o[3] = 255;
                }
            }
            _ => {
                return Err(format!(
                    "unsupported X image layout ({bpp} bytes/pixel); \
                     screenshot the QR to a file and import that instead"
                ));
            }
        }
        Ok(out)
    }

    /// Ask xdg-desktop-portal for a screenshot; it writes a PNG and returns a
    /// `file://` URI. `ashpd` is async, so drive it to completion with
    /// `pollster` on this (import) thread — the same bridge the app already uses
    /// for rfd's portal dialogs.
    fn wayland_portal() -> Result<Vec<u8>, String> {
        use ashpd::desktop::screenshot::Screenshot;

        let uri = pollster::block_on(async {
            Screenshot::request()
                .interactive(false)
                .modal(false)
                .send()
                .await
                .map_err(|e| format!("screenshot portal request failed: {e}"))?
                .response()
                .map(|s| s.uri().as_str().to_owned())
                .map_err(|e| format!("screenshot portal returned no image: {e}"))
        })?;

        let path = file_uri_to_path(&uri)?;
        let bytes =
            std::fs::read(&path).map_err(|e| format!("cannot read the portal screenshot: {e}"))?;
        // The portal wrote a temp file for us; remove it once read.
        let _ = std::fs::remove_file(&path);
        Ok(bytes)
    }

    /// Turn a `file://` URI (as the portal returns) into a path. Handles an
    /// optional authority (`file://host/path`) and percent-decoding, so we don't
    /// pull in the `url` crate for one field.
    fn file_uri_to_path(uri: &str) -> Result<std::path::PathBuf, String> {
        let rest = uri
            .strip_prefix("file://")
            .ok_or_else(|| format!("portal returned a non-file URI: {uri}"))?;
        let path_part = match rest.find('/') {
            Some(i) => &rest[i..], // skips any host component before the first '/'
            None => return Err(format!("malformed file URI: {uri}")),
        };
        Ok(std::path::PathBuf::from(percent_decode(path_part)))
    }

    fn percent_decode(s: &str) -> String {
        let b = s.as_bytes();
        let mut out = Vec::with_capacity(b.len());
        let mut i = 0;
        while i < b.len() {
            if b[i] == b'%' && i + 2 < b.len() {
                if let (Some(hi), Some(lo)) = (hex_val(b[i + 1]), hex_val(b[i + 2])) {
                    out.push(hi * 16 + lo);
                    i += 3;
                    continue;
                }
            }
            out.push(b[i]);
            i += 1;
        }
        String::from_utf8_lossy(&out).into_owned()
    }

    fn hex_val(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// macOS: shell out to the built-in screen grabber (no crate, no permission
// plumbing beyond the OS's own screen-recording prompt).
// ---------------------------------------------------------------------------
#[cfg(target_os = "macos")]
mod macos {
    use super::Capture;
    use crate::private_tmp::PrivateTempDir;

    /// How many output names to hand `screencapture`. It writes one file per
    /// display, in display order, and ignores names beyond the display count,
    /// so this is the most displays one scan covers.
    const MAX_DISPLAYS: usize = 8;

    pub fn capture() -> Result<Vec<Capture>, String> {
        // The screenshots may contain a 2FA QR (a seed), so they go in a
        // fresh owner-only directory that is removed, files and all, when
        // `dir` drops — on success, on a read error, on a non-zero exit and
        // when screencapture can't even be started.
        let dir = PrivateTempDir::new("keyroost-screengrab")
            .map_err(|e| format!("cannot create a private folder for the capture: {e}"))?;
        let files: Vec<std::path::PathBuf> = (1..=MAX_DISPLAYS)
            .map(|i| dir.path().join(format!("screen-{i}.png")))
            .collect();
        // `-x` silences the shutter sound; `-t png` picks the format.
        let status = std::process::Command::new("/usr/sbin/screencapture")
            .args(["-x", "-t", "png"])
            .args(&files)
            .status()
            .map_err(|e| format!("could not run screencapture: {e}"))?;
        if !status.success() {
            return Err(
                "screencapture failed — grant keyroost Screen Recording permission and retry"
                    .into(),
            );
        }
        // One file per display; names past the display count stay absent.
        let mut captures = Vec::new();
        for file in &files {
            match std::fs::read(file) {
                Ok(bytes) => captures.push(Capture::Png(bytes)),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(format!("cannot read the capture: {e}")),
            }
        }
        Ok(captures)
    }
}

// ---------------------------------------------------------------------------
// Windows: delegate to keyroost-screengrab, which owns the unsafe GDI FFI (this
// crate forbids unsafe code).
// ---------------------------------------------------------------------------
#[cfg(target_os = "windows")]
mod windows_gdi {
    use super::Capture;

    pub fn capture() -> Result<Vec<Capture>, String> {
        let frame = keyroost_screengrab::capture_virtual_screen()?;
        Ok(vec![Capture::Rgba {
            width: frame.width,
            height: frame.height,
            data: frame.rgba,
        }])
    }
}
