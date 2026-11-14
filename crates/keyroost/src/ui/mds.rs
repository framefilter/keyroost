// crates/keyroost/src/ui/mds.rs
//
// Icons for the FIDO metadata card. The metadata itself (the bundled MDS
// dataset and its lookup) lives in `keyroost_resolve::mds`, shared with the
// CLI; decoding the icon into a texture is the app's own part.

/// Decode a `data:image/png;base64,...` icon URI to an `egui::ColorImage`.
/// Returns `None` for non-PNG icons, malformed data, or decode errors — callers
/// simply omit the image in that case. Only PNG is handled: every icon in the
/// MDS BLOB is a PNG data URI per the metadata statement spec.
pub fn decode_icon(data_uri: &str) -> Option<egui::ColorImage> {
    let b64 = data_uri
        .strip_prefix("data:image/png;base64,")
        .or_else(|| data_uri.strip_prefix("data:image/png;charset=utf-8;base64,"))?;
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .ok()?;
    let ([w, h], rgba) = decode_png_rgba(&bytes)?;
    Some(egui::ColorImage::from_rgba_unmultiplied([w, h], &rgba))
}

/// Decode PNG bytes to `([width, height], RGBA8 pixels)`. `None` on a decode
/// error or a pixel format this doesn't expand; the buffer is always exactly
/// `width * height * 4` bytes.
pub fn decode_png_rgba(bytes: &[u8]) -> Option<([usize; 2], Vec<u8>)> {
    let mut decoder = png::Decoder::new(std::io::Cursor::new(bytes));
    // png 0.17+ applies no transformations by default, so a palette image (many
    // vendor icons, Feitian's among them) would come back as raw indices. Expand
    // to 8-bit gray / RGB(A), as `keyroost-qr` does.
    decoder.set_transformations(png::Transformations::EXPAND | png::Transformations::STRIP_16);
    let mut reader = decoder.read_info().ok()?;
    let mut buf = vec![0u8; reader.output_buffer_size()?];
    let frame = reader.next_frame(&mut buf).ok()?;
    let (w, h) = (frame.width as usize, frame.height as usize);
    let data = &buf[..frame.buffer_size()];
    // Normalize to RGBA8 for egui.
    let rgba: Vec<u8> = match frame.color_type {
        png::ColorType::Rgba => data.to_vec(),
        png::ColorType::Rgb => data
            .as_chunks::<3>()
            .0
            .iter()
            .flat_map(|p| [p[0], p[1], p[2], 255])
            .collect(),
        png::ColorType::GrayscaleAlpha => data
            .as_chunks::<2>()
            .0
            .iter()
            .flat_map(|p| [p[0], p[0], p[0], p[1]])
            .collect(),
        png::ColorType::Grayscale => data.iter().flat_map(|&g| [g, g, g, 255]).collect(),
        // EXPAND above turns palette images into Rgb/Rgba, so nothing else is
        // expected; bail rather than render garbage.
        _ => return None,
    };
    // `ColorImage::from_rgba_unmultiplied` asserts the buffer is exactly w*h*4;
    // bail with None on any mismatch rather than risk a panic in the UI thread.
    if rgba.len() != w * h * 4 {
        return None;
    }
    Some(([w, h], rgba))
}

#[cfg(test)]
mod tests {
    use super::decode_png_rgba;

    /// A 2x2 8-bit palette PNG (the format many vendor MDS icons use, e.g. Feitian's),
    /// with an optional tRNS chunk.
    fn indexed_png(trns: Option<&[u8]>) -> Vec<u8> {
        let mut out = Vec::new();
        let mut enc = png::Encoder::new(&mut out, 2, 2);
        enc.set_color(png::ColorType::Indexed);
        enc.set_depth(png::BitDepth::Eight);
        enc.set_palette(vec![255, 0, 0, 0, 255, 0, 0, 0, 255, 10, 20, 30]);
        if let Some(t) = trns {
            enc.set_trns(t.to_vec());
        }
        let mut w = enc.write_header().unwrap();
        w.write_image_data(&[0, 1, 2, 3]).unwrap();
        w.finish().unwrap();
        out
    }

    #[test]
    fn palette_png_expands_to_rgba() {
        let (size, rgba) = decode_png_rgba(&indexed_png(None)).expect("palette PNG decodes");
        assert_eq!(size, [2, 2]);
        assert_eq!(
            rgba,
            [255, 0, 0, 255, 0, 255, 0, 255, 0, 0, 255, 255, 10, 20, 30, 255]
        );
    }

    #[test]
    fn palette_png_keeps_trns_alpha() {
        let (_, rgba) =
            decode_png_rgba(&indexed_png(Some(&[0, 128]))).expect("palette PNG decodes");
        // Entries 0 and 1 carry alpha 0 and 128; tRNS leaves the rest opaque.
        let alpha: Vec<u8> = rgba.chunks(4).map(|p| p[3]).collect();
        assert_eq!(alpha, [0, 128, 255, 255]);
    }
}
