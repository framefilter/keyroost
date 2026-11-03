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
    let decoder = png::Decoder::new(std::io::Cursor::new(bytes));
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
        // Indexed/other should already be expanded by png's transformations in
        // the common case; bail rather than render garbage.
        _ => return None,
    };
    // `ColorImage::from_rgba_unmultiplied` asserts the buffer is exactly w*h*4;
    // bail with None on any mismatch rather than risk a panic in the UI thread.
    if rgba.len() != w * h * 4 {
        return None;
    }
    Some(([w, h], rgba))
}
