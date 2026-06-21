//! Scan a TOTP QR code from the screen(s) (feature `qr`).
//!
//! Captures every connected display as PNG and hands the bytes to
//! `keyroost_qr::texts_from_image`, the crate the app already uses to decode QR
//! screenshots from files — so the screen path and the file/paste paths share
//! one decoder and one parser. The only capability this module adds is grabbing
//! the screen; decoding and otpauth parsing are entirely reused.
//!
//! Capture and decode happen locally — nothing is sent anywhere.

/// Capture all screens and return the first `otpauth://totp` URI found, or an
/// error describing why nothing usable was scanned. The returned string is the
/// raw URI, to be fed to `keyroost_import::parse_otpauth` like a pasted URI.
pub fn scan_screens_for_otpauth() -> Result<String, String> {
    let screens =
        screenshots::Screen::all().map_err(|e| format!("could not enumerate screens: {e}"))?;
    if screens.is_empty() {
        return Err("no screens available to scan".into());
    }

    let mut found_any_qr = false;
    let mut saw_hotp = false;

    for screen in screens {
        let image = match screen.capture() {
            Ok(img) => img,
            Err(_) => continue, // skip a screen we can't grab
        };
        // `screenshots` returns PNG-encoded bytes; keyroost-qr decodes PNG/JPEG.
        let png = image.buffer();
        let texts = match keyroost_qr::texts_from_image(png) {
            Ok(t) => t,
            Err(_) => continue,
        };
        for text in texts.iter() {
            let trimmed = text.trim();
            let lower = trimmed.to_ascii_lowercase();
            if lower.starts_with("otpauth://totp/") {
                return Ok(trimmed.to_string());
            }
            if lower.starts_with("otpauth://") {
                found_any_qr = true;
                if lower.starts_with("otpauth://hotp/") {
                    saw_hotp = true;
                }
            } else if !trimmed.is_empty() {
                found_any_qr = true;
            }
        }
    }

    if saw_hotp {
        Err("this is an HOTP code; only TOTP is supported".into())
    } else if found_any_qr {
        Err("a QR code was found, but it isn't a TOTP (otpauth://totp) code".into())
    } else {
        Err("no QR code found on screen — make sure the TOTP QR is visible".into())
    }
}
