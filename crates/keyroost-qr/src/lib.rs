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

pub mod file;

pub use file::{open_file, OpenError, Opened};

use keyroost_import::migration;
use keyroost_import::{BulkEntry, BulkError, Format, ImportFile, ImportItem, OtpAuth, Unusable};

/// Refuse images larger than this many pixels before allocating the
/// grayscale buffer. 16 MP comfortably covers any screenshot (a 4K display
/// is ~8.3 MP) while bounding a hostile file's memory demand at 16 MiB.
const MAX_PIXELS: u64 = 16_000_000;

#[non_exhaustive]
#[derive(Debug)]
pub enum QrError {
    /// Not a PNG or JPEG (by magic bytes).
    UnsupportedImage,
    /// The image decodes but exceeds the internal `MAX_PIXELS` cap.
    ImageTooLarge { width: u32, height: u32 },
    /// PNG/JPEG decoding failed.
    ImageDecode(String),
    /// No QR code was found in the image.
    NoQrFound,
    /// A QR was found but its payload isn't an otpauth/migration URI.
    NotOtpauth,
    /// The payload parsed as otpauth/migration but was invalid.
    Payload(String),
    /// The codes in the image carry more than
    /// [`MAX_ENTRIES`](keyroost_import::entry::MAX_ENTRIES) accounts (wide
    /// reading only).
    TooManyEntries,
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
            QrError::TooManyEntries => write!(f, "{}", keyroost_import::BulkError::TooManyEntries),
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
/// The payloads of 2FA QRs are seeds in clear text, so they come back in a
/// wipe-on-drop buffer — callers don't get to forget.
pub fn texts_from_image(bytes: &[u8]) -> Result<zeroize::Zeroizing<Vec<String>>, QrError> {
    let (w, h, luma) = to_grayscale(bytes)?;
    texts_from_luma(w, h, &luma)
}

/// Decode every QR code from a raw RGBA8 pixel buffer — e.g. a live screen
/// capture that arrives already decoded, so PNG/JPEG decoding is skipped.
/// `rgba` must be exactly `width * height * 4` bytes. Same wipe-on-drop output
/// contract as [`texts_from_image`]; the internal `MAX_PIXELS` cap is enforced
/// before the luma allocation.
pub fn texts_from_rgba(
    width: u32,
    height: u32,
    rgba: &[u8],
) -> Result<zeroize::Zeroizing<Vec<String>>, QrError> {
    let pixels = width as u64 * height as u64;
    if pixels > MAX_PIXELS {
        return Err(QrError::ImageTooLarge { width, height });
    }
    let expected = pixels as usize * 4;
    if rgba.len() != expected {
        return Err(QrError::ImageDecode(format!(
            "RGBA buffer is {} bytes, expected {expected} for {width}x{height}",
            rgba.len()
        )));
    }
    // Rec. 601 luma, integer approximation — rqrr only needs contrast, and this
    // mirrors the grayscale the PNG/JPEG file path already produces.
    let mut luma = vec![0u8; pixels as usize];
    for (dst, px) in luma.iter_mut().zip(rgba.chunks_exact(4)) {
        let (r, g, b) = (px[0] as u32, px[1] as u32, px[2] as u32);
        *dst = ((r * 77 + g * 150 + b * 29) >> 8) as u8;
    }
    texts_from_luma(width, height, &luma)
}

/// Shared rqrr detection + decode over an 8-bit luma buffer, used by both the
/// PNG/JPEG file path and the raw-RGBA screen-capture path.
fn texts_from_luma(
    w: u32,
    h: u32,
    luma: &[u8],
) -> Result<zeroize::Zeroizing<Vec<String>>, QrError> {
    let mut img = rqrr::PreparedImage::prepare_from_greyscale(w as usize, h as usize, |x, y| {
        luma[y * w as usize + x]
    });
    let grids = img.detect_grids();
    if grids.is_empty() {
        return Err(QrError::NoQrFound);
    }
    let mut out = zeroize::Zeroizing::new(Vec::new());
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
    // they arrive in (and stay in) a wipe-on-drop buffer.
    let texts = texts_from_image(bytes)?;
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

/// Decode a QR image into the wide, format-neutral model: every account in
/// every code, in order — HOTP, any TOTP period and SHA-512 included — each
/// usable or marked with why not. A damaged Google Authenticator code
/// becomes an unusable item rather than discarding the other codes. Same
/// whole-image errors as [`entries_from_image`]: no 2FA code at all is
/// [`QrError::NotOtpauth`], and only damaged codes is [`QrError::Payload`].
pub fn entries_from_image_wide(bytes: &[u8]) -> Result<ImportFile, QrError> {
    let texts = texts_from_image(bytes)?;
    file_from_texts(&texts)
}

/// The routing half of [`entries_from_image_wide`], over decoded payloads.
fn file_from_texts(texts: &[String]) -> Result<ImportFile, QrError> {
    let mut items: Vec<ImportItem> = Vec::new();
    let mut batch = None;
    let mut any_otpauth = false;
    let mut any_migration = false;
    let mut any_parsed = false;
    let mut payload_err: Option<String> = None;
    for text in texts {
        // Refuse before building the next item (see `MAX_ENTRIES`).
        if items.len() >= keyroost_import::entry::MAX_ENTRIES {
            return Err(QrError::TooManyEntries);
        }
        let text = text.trim();
        if migration::is_migration_uri(text) {
            any_otpauth = true;
            any_migration = true;
            match migration::parse_wide(text) {
                Err(BulkError::TooManyEntries) => return Err(QrError::TooManyEntries),
                Ok(file) => {
                    if items.len() + file.items.len() > keyroost_import::entry::MAX_ENTRIES {
                        return Err(QrError::TooManyEntries);
                    }
                    any_parsed = true;
                    batch = batch.or(file.batch);
                    items.extend(file.items);
                }
                Err(e) => {
                    payload_err.get_or_insert(e.to_string());
                    items.push(ImportItem {
                        index: 0,
                        label: "damaged QR code".into(),
                        entry: Err(Unusable::Malformed("QR payload could not be read")),
                    });
                }
            }
        } else if text.starts_with("otpauth://") {
            any_otpauth = true;
            any_parsed = true;
            let (label, entry) = keyroost_import::otpauth::parse_entry_labeled(text);
            items.push(ImportItem {
                index: 0,
                label: label.unwrap_or_default(),
                entry,
            });
        }
    }
    if !any_otpauth {
        return Err(QrError::NotOtpauth);
    }
    if !any_parsed {
        if let Some(e) = payload_err {
            return Err(QrError::Payload(e));
        }
    }
    // One running index across every code in the image; nameless items are
    // named by their position.
    for (i, item) in items.iter_mut().enumerate() {
        item.index = i;
        if item.label.is_empty() {
            item.label = format!("entry {}", i + 1);
        }
    }
    Ok(ImportFile {
        format: if any_migration {
            Format::GoogleExport
        } else {
            Format::QrImage
        },
        items,
        batch,
    })
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

    fn texts(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn wide_damaged_code_is_an_item_not_a_failure() {
        let f = file_from_texts(&texts(&[
            "otpauth://hotp/Acme:alice?secret=JBSWY3DPEHPK3PXP&counter=4",
            "otpauth-migration://offline?data=!!!",
            "otpauth://steam/Game?secret=JBSWY3DPEHPK3PXP",
            "https://not.a.code",
        ]))
        .unwrap();
        assert_eq!(f.format, Format::GoogleExport);
        let shape: Vec<_> = f
            .items
            .iter()
            .map(|i| (i.index, i.label.as_str(), i.entry.as_ref().err().cloned()))
            .collect();
        assert_eq!(
            shape,
            [
                (0, "Acme:alice", None),
                (
                    1,
                    "damaged QR code",
                    Some(Unusable::Malformed("QR payload could not be read"))
                ),
                (2, "Game", Some(Unusable::Type("steam".into()))),
            ]
        );
    }

    #[test]
    fn wide_refuses_more_than_max_entries() {
        let code = "otpauth://totp/X?secret=JBSWY3DP".to_string();
        let at_cap = vec![code.clone(); keyroost_import::entry::MAX_ENTRIES];
        assert_eq!(file_from_texts(&at_cap).unwrap().items.len(), at_cap.len());
        let over = vec![code; keyroost_import::entry::MAX_ENTRIES + 1];
        assert!(matches!(
            file_from_texts(&over),
            Err(QrError::TooManyEntries)
        ));
    }

    #[test]
    fn wide_whole_image_errors_match_the_narrow_path() {
        assert!(matches!(
            file_from_texts(&texts(&["https://example.com"])),
            Err(QrError::NotOtpauth)
        ));
        assert!(matches!(
            file_from_texts(&texts(&["otpauth-migration://offline?data=!!!"])),
            Err(QrError::Payload(_))
        ));
        let f = file_from_texts(&texts(&["otpauth://totp/X?secret=JBSWY3DP&period=45"])).unwrap();
        assert_eq!(f.format, Format::QrImage);
        assert_eq!(f.usable(), 1);
    }

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
