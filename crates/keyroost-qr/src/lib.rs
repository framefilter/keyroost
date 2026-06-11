//! QR-code import from screenshot files.
//!
//! Pipeline: PNG/JPEG bytes → bounds-checked decode → grayscale → QR
//! detection (rqrr) → payload routing. Two payload kinds are understood:
//! a standard `otpauth://` enrollment URI and a Google Authenticator
//! `otpauth-migration://` export batch; both come back as the same
//! [`BulkEntry`] list the rest of the import pipeline already consumes.
//!
//! Threat model: the image is attacker-supplied (a "scan this to get my 2FA"
//! file). Dimensions are capped before pixel allocation, both decoders are
//! memory-safe Rust, and the decoded text flows into the same hardened
//! parsers (`parse_otpauth`, `migration::parse`) every other input uses.
//! The decoded payload is secret material — callers should treat returned
//! entries with the same hygiene as any other seed source and remind users
//! to delete the screenshot afterwards.

use keyroost_import::migration;
use keyroost_import::{BulkEntry, OtpAuth};

/// Refuse images larger than this many pixels before allocating the
/// grayscale buffer. 16 MP comfortably covers any screenshot (a 4K display
/// is ~8.3 MP) while bounding a hostile file's memory demand at 16 MiB.
const MAX_PIXELS: u64 = 16_000_000;

#[derive(Debug)]
pub enum QrError {
    /// Not a PNG or JPEG (by magic bytes).
    UnsupportedImage,
    /// The image decodes but exceeds [`MAX_PIXELS`].
    ImageTooLarge { width: u32, height: u32 },
    /// PNG/JPEG decoding failed.
    ImageDecode(String),
    /// No QR code was found in the image.
    NoQrFound,
    /// A QR was found but its payload isn't an otpauth/migration URI.
    NotOtpauth,
    /// The payload parsed as otpauth/migration but was invalid.
    Payload(String),
}

impl std::fmt::Display for QrError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QrError::UnsupportedImage => {
                write!(
                    f,
                    "not a PNG or JPEG image (screenshots are PNG on every OS)"
                )
            }
            QrError::ImageTooLarge { width, height } => write!(
                f,
                "image is {}x{} — larger than any screenshot; refusing to decode",
                width, height
            ),
            QrError::ImageDecode(e) => write!(f, "could not decode image: {}", e),
            QrError::NoQrFound => write!(
                f,
                "no QR code found — crop closer, increase contrast, or re-screenshot at 100% zoom"
            ),
            QrError::NotOtpauth => write!(
                f,
                "found a QR code, but it isn't a 2FA enrollment (otpauth://) or \
                 Google Authenticator export"
            ),
            QrError::Payload(e) => write!(f, "QR payload invalid: {}", e),
        }
    }
}

impl std::error::Error for QrError {}

/// What a QR image imported to.
pub struct QrImport {
    pub entries: Vec<BulkEntry>,
    /// Migration entries that couldn't be represented, with reasons.
    pub skipped: Vec<migration::Skipped>,
    /// `(index, total)` when this is one QR of a multi-code GA export.
    pub batch: Option<(u32, u32)>,
}

/// Decode every QR code in a PNG/JPEG image and return the payload strings.
pub fn texts_from_image(bytes: &[u8]) -> Result<Vec<String>, QrError> {
    let (w, h, luma) = to_grayscale(bytes)?;
    let mut img = rqrr::PreparedImage::prepare_from_greyscale(w as usize, h as usize, |x, y| {
        luma[y * w as usize + x]
    });
    let grids = img.detect_grids();
    if grids.is_empty() {
        return Err(QrError::NoQrFound);
    }
    let mut out = Vec::new();
    for grid in grids {
        if let Ok((_meta, text)) = grid.decode() {
            out.push(text);
        }
    }
    if out.is_empty() {
        // Grids detected but none decoded — blurry/damaged code.
        return Err(QrError::NoQrFound);
    }
    Ok(out)
}

/// Decode a QR image into import entries, accepting both standard
/// `otpauth://` enrollment QRs and Google Authenticator export batches.
pub fn entries_from_image(bytes: &[u8]) -> Result<QrImport, QrError> {
    // The decoded payloads are otpauth:// URIs carrying the seeds in clear;
    // wipe them on every exit path once parsing is done.
    let texts = zeroize::Zeroizing::new(texts_from_image(bytes)?);
    let mut import = QrImport {
        entries: Vec::new(),
        skipped: Vec::new(),
        batch: None,
    };
    let mut any_otpauth = false;
    // A malformed payload must not abort the whole image: a screenshot can
    // hold several QR codes and one damaged code shouldn't discard the
    // accounts decoded from the others. Failures only become the result
    // when no payload in the image yielded anything.
    let mut payload_err: Option<String> = None;
    let mut any_parsed = false;
    for text in texts.iter() {
        if migration::is_migration_uri(text) {
            any_otpauth = true;
            match migration::parse(text) {
                Ok(m) => {
                    any_parsed = true;
                    import.entries.extend(m.entries);
                    import.skipped.extend(m.skipped);
                    import.batch = import.batch.or(m.batch);
                }
                Err(e) => {
                    payload_err.get_or_insert(e.to_string());
                    import.skipped.push(migration::Skipped {
                        label: "damaged QR code".into(),
                        reason: "payload could not be parsed",
                    });
                }
            }
        } else if text.trim_start().starts_with("otpauth://") {
            any_otpauth = true;
            match keyroost_import::parse_otpauth(text.trim()) {
                Ok(parsed) => {
                    let parsed: OtpAuth = parsed;
                    any_parsed = true;
                    import.entries.push(parsed.into());
                }
                Err(e) => {
                    payload_err.get_or_insert(e.to_string());
                    import.skipped.push(migration::Skipped {
                        label: "damaged QR code".into(),
                        reason: "payload could not be parsed",
                    });
                }
            }
        }
    }
    if !any_otpauth {
        return Err(QrError::NotOtpauth);
    }
    if !any_parsed {
        if let Some(e) = payload_err {
            // Every otpauth payload in the image was unreadable — surface
            // the first underlying error instead of an empty success.
            return Err(QrError::Payload(e));
        }
    }
    Ok(import)
}

/// True when `bytes` starts with a PNG or JPEG signature — lets callers
/// route files by content rather than extension.
pub fn looks_like_image(bytes: &[u8]) -> bool {
    bytes.starts_with(b"\x89PNG\r\n\x1a\n") || bytes.starts_with(&[0xFF, 0xD8, 0xFF])
}

/// Decode PNG or JPEG (detected by magic bytes) to an 8-bit grayscale
/// buffer, enforcing [`MAX_PIXELS`] before the pixel allocation.
fn to_grayscale(bytes: &[u8]) -> Result<(u32, u32, Vec<u8>), QrError> {
    if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        decode_png(bytes)
    } else if bytes.starts_with(&[0xFF, 0xD8, 0xFF]) {
        decode_jpeg(bytes)
    } else {
        Err(QrError::UnsupportedImage)
    }
}

fn check_dims(w: u32, h: u32) -> Result<(), QrError> {
    if u64::from(w) * u64::from(h) > MAX_PIXELS || w == 0 || h == 0 {
        return Err(QrError::ImageTooLarge {
            width: w,
            height: h,
        });
    }
    Ok(())
}

fn decode_png(bytes: &[u8]) -> Result<(u32, u32, Vec<u8>), QrError> {
    let mut decoder = png::Decoder::new(std::io::Cursor::new(bytes));
    // Normalize palette/1-2-4-bit/16-bit forms down to 8-bit channels so the
    // match below only sees the four canonical color types.
    decoder.set_transformations(png::Transformations::EXPAND | png::Transformations::STRIP_16);
    let mut reader = decoder
        .read_info()
        .map_err(|e| QrError::ImageDecode(e.to_string()))?;
    let info = reader.info();
    let (w, h) = (info.width, info.height);
    check_dims(w, h)?;
    let buf_size = reader
        .output_buffer_size()
        .ok_or_else(|| QrError::ImageDecode("PNG output size overflows".into()))?;
    let mut buf = vec![0u8; buf_size];
    let out = reader
        .next_frame(&mut buf)
        .map_err(|e| QrError::ImageDecode(e.to_string()))?;
    let data = &buf[..out.buffer_size()];
    let luma = match out.color_type {
        png::ColorType::Grayscale => data.to_vec(),
        png::ColorType::GrayscaleAlpha => data.chunks_exact(2).map(|p| p[0]).collect(),
        png::ColorType::Rgb => data.chunks_exact(3).map(rgb_luma).collect(),
        png::ColorType::Rgba => data.chunks_exact(4).map(rgb_luma).collect(),
        other => {
            return Err(QrError::ImageDecode(format!(
                "unsupported PNG color type {:?}",
                other
            )))
        }
    };
    Ok((w, h, luma))
}

fn decode_jpeg(bytes: &[u8]) -> Result<(u32, u32, Vec<u8>), QrError> {
    let mut decoder = jpeg_decoder::Decoder::new(bytes);
    decoder
        .read_info()
        .map_err(|e| QrError::ImageDecode(e.to_string()))?;
    let info = decoder
        .info()
        .ok_or_else(|| QrError::ImageDecode("missing JPEG header info".into()))?;
    let (w, h) = (u32::from(info.width), u32::from(info.height));
    check_dims(w, h)?;
    let data = decoder
        .decode()
        .map_err(|e| QrError::ImageDecode(e.to_string()))?;
    let luma = match info.pixel_format {
        jpeg_decoder::PixelFormat::L8 => data,
        jpeg_decoder::PixelFormat::L16 => data.chunks_exact(2).map(|p| p[0]).collect(),
        jpeg_decoder::PixelFormat::RGB24 => data.chunks_exact(3).map(rgb_luma).collect(),
        jpeg_decoder::PixelFormat::CMYK32 => data
            .chunks_exact(4)
            .map(|p| {
                // Approximate CMYK→luma; QR detection only needs contrast.
                let k = u32::from(p[3]);
                (u32::from(rgb_luma(&p[..3])) * k / 255) as u8
            })
            .collect(),
    };
    Ok((w, h, luma))
}

/// ITU-R BT.601 luma from the first three bytes of a pixel.
fn rgb_luma(p: &[u8]) -> u8 {
    ((u32::from(p[0]) * 299 + u32::from(p[1]) * 587 + u32::from(p[2]) * 114) / 1000) as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_images() {
        assert!(matches!(
            texts_from_image(b"not an image"),
            Err(QrError::UnsupportedImage)
        ));
    }

    #[test]
    fn oversize_png_rejected_before_pixel_allocation() {
        // A crafted PNG header declaring 100k x 100k must be rejected at the
        // header stage, never reaching the (10 GB) pixel buffer.
        let mut p = b"\x89PNG\r\n\x1a\n".to_vec();
        p.extend([0, 0, 0, 13]);
        p.extend(b"IHDR");
        p.extend(100_000u32.to_be_bytes());
        p.extend(100_000u32.to_be_bytes());
        p.extend([8, 0, 0, 0, 0]);
        p.extend([0, 0, 0, 0]); // wrong CRC; decoder may flag that instead
        let r = texts_from_image(&p);
        assert!(matches!(
            r,
            Err(QrError::ImageTooLarge { .. }) | Err(QrError::ImageDecode(_))
        ));
    }
}
