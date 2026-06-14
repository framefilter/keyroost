//! Token2 OTP USB-HID framing (spec §4).
//!
//! This is **not** CTAP-HID. The OTP applet wraps APDUs in its own 64-byte
//! feature-report frames. The authoritative send construction is spec §4.3
//! step 4: the 64-byte payload is
//!
//! ```text
//! 21 || (flags|seq) || len || chunk[..=61] || zero-pad
//! ```
//!
//! and the host then prepends a `0x00` HID report-ID byte (step 5), making the
//! on-wire write 65 bytes. So within the 65-byte buffer: byte 0 is the report
//! ID, byte 1 is the `0x21` magic, byte 2 is flags+sequence, byte 3 is the chunk
//! length (≤ 61 — the room left in 64 bytes after the 3-byte header), and bytes
//! 4.. are the chunk.
//!
//! The device may answer a long-running command with `0xC0` "still working"
//! frames that the host must poll past without advancing its sequence counter
//! (spec §4.4 step 3).
//!
//! > **Note on the §4.1 vs §4.3 wording.** The offset table in §4.1 counts the
//! > report-ID byte as "offset 0" *inside* the 64-byte payload, which makes the
//! > magic look two bytes wide (`00 21`). §4.3 step 4 is unambiguous that the
//! > payload itself starts with a single `21` magic byte; the leading `00` is
//! > the report ID added in step 5. We follow §4.3. On the receive side we let
//! > the caller hand us the payload already positioned at the `21` magic so we
//! > work whether or not the platform HID stack kept the report-ID byte (§4.4
//! > step 1 explicitly allows for both).
//!
//! The logic here is transport-agnostic: [`build_send_frames`] turns an APDU
//! into the 65-byte reports to write, and [`ResponseAssembler`] consumes
//! received payloads and tells the caller whether to keep reading, poll again,
//! or stop. The `read`/`write` syscalls and the platform HID backend live in
//! `keyroost-transport`.

/// HID report size: 64 payload bytes. The host write is 65 bytes (leading `0x00`
/// report ID).
pub const REPORT_PAYLOAD: usize = 64;
/// Bytes of header inside the 64-byte payload before chunk data: magic(1) +
/// flags/seq(1) + len(1) = 3 (spec §4.3 step 4).
pub const PAYLOAD_HEADER: usize = 3;
/// Maximum useful APDU bytes per frame: `64 - 3 = 61` (spec §4.3 step 2).
pub const MAX_CHUNK: usize = REPORT_PAYLOAD - PAYLOAD_HEADER;

/// The single magic byte that opens every 64-byte payload (spec §4.3 step 4).
pub const MAGIC: u8 = 0x21;

/// Flag nibble (high 4 bits of the flags/seq byte) — more chunks follow.
pub const FLAG_MORE: u8 = 0x20;
/// Flag nibble — device still working; host should poll again (device→host).
pub const FLAG_BUSY: u8 = 0xC0;
/// Flag nibble — last/only chunk.
pub const FLAG_LAST: u8 = 0x00;

/// Build the sequence of 65-byte output reports for one APDU (spec §4.3).
///
/// Each buffer is ready to hand to a HID `write`: byte 0 is the `0x00` report
/// ID, byte 1 is the `0x21` magic, byte 2 is `flags|seq`, byte 3 is the chunk
/// length, then the chunk, zero-padded to 65 bytes.
pub fn build_send_frames(apdu: &[u8]) -> Vec<[u8; REPORT_PAYLOAD + 1]> {
    if apdu.is_empty() {
        let mut frame = [0u8; REPORT_PAYLOAD + 1];
        frame[1] = MAGIC;
        frame[2] = FLAG_LAST;
        frame[3] = 0;
        return vec![frame];
    }

    let mut frames = Vec::new();
    let total_chunks = apdu.len().div_ceil(MAX_CHUNK);
    for (i, chunk) in apdu.chunks(MAX_CHUNK).enumerate() {
        let is_last = i + 1 == total_chunks;
        let flags = if is_last { FLAG_LAST } else { FLAG_MORE };
        let seq = (i % 16) as u8;
        let mut frame = [0u8; REPORT_PAYLOAD + 1];
        frame[0] = 0x00; // report ID
        frame[1] = MAGIC; // payload byte 0
        frame[2] = flags | seq; // payload byte 1
        frame[3] = chunk.len() as u8; // payload byte 2
        frame[4..4 + chunk.len()].copy_from_slice(chunk);
        frames.push(frame);
    }
    frames
}

/// What the caller should do after offering a received frame to the assembler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// More response frames are expected — read another report.
    NeedMore,
    /// Device is busy (a `0xC0` frame was seen). Read another report; do not
    /// advance state. `retries` counts consecutive busy frames so the caller can
    /// fire a "press the button" prompt at ~3 (spec §4.4 step 3).
    Busy { retries: u32 },
    /// The response is complete; call [`ResponseAssembler::into_response`].
    Done,
}

/// Errors surfaced while assembling a HID response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameError {
    /// The magic byte was not `0x21`.
    BadMagic,
    /// The chunk-length byte exceeded the 61-byte maximum.
    ChunkTooLong(u8),
    /// A continuation frame arrived with an unexpected sequence number.
    OutOfSequence { expected: u8, got: u8 },
    /// The frame was shorter than the 3-byte payload header it must contain.
    ShortFrame,
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FrameError::BadMagic => write!(f, "HID frame magic byte was not 0x21"),
            FrameError::ChunkTooLong(n) => write!(f, "HID chunk length {} exceeds 61", n),
            FrameError::OutOfSequence { expected, got } => write!(
                f,
                "HID frame out of sequence: expected {}, got {}",
                expected, got
            ),
            FrameError::ShortFrame => write!(f, "HID frame shorter than its 3-byte header"),
        }
    }
}

impl std::error::Error for FrameError {}

/// Reassembles a multi-frame device response (spec §4.4).
///
/// The caller passes the 64-byte payload positioned so that byte 0 is the `0x21`
/// magic — i.e. with the report-ID byte stripped if the platform kept it. This
/// matches §4.4 step 1's allowance for stacks that do or don't surface the
/// report ID.
#[derive(Default)]
pub struct ResponseAssembler {
    buf: Vec<u8>,
    received: u8,
    busy_retries: u32,
    done: bool,
}

impl ResponseAssembler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Offer one received report. Accepts either alignment: a buffer that still
    /// has the leading `0x00` HID report-ID byte (so `[0]=0x00, [1]=0x21`, as the
    /// Windows/macOS feature-report path delivers it) or one already positioned
    /// at the `0x21` magic (as Linux hidraw delivers it). The magic position is
    /// detected per frame.
    pub fn push(&mut self, raw: &[u8]) -> Result<Step, FrameError> {
        // Locate the magic: if byte 0 is the report ID 0x00 and byte 1 is the
        // magic, the real payload starts at offset 1; otherwise it starts at 0.
        let payload: &[u8] = if raw.first() == Some(&0x00) && raw.get(1) == Some(&MAGIC) {
            &raw[1..]
        } else {
            raw
        };

        if payload.len() < PAYLOAD_HEADER {
            return Err(FrameError::ShortFrame);
        }
        if payload[0] != MAGIC {
            return Err(FrameError::BadMagic);
        }
        let flags = payload[1] & 0xF0;
        let seq = payload[1] & 0x0F;

        // Busy: do not append, do not advance the counter (spec §4.4 step 3).
        if flags == FLAG_BUSY {
            self.busy_retries += 1;
            return Ok(Step::Busy {
                retries: self.busy_retries,
            });
        }
        self.busy_retries = 0;

        if seq != self.received % 16 {
            return Err(FrameError::OutOfSequence {
                expected: self.received % 16,
                got: seq,
            });
        }
        self.received = self.received.wrapping_add(1);

        let len = payload[2];
        if len as usize > MAX_CHUNK {
            return Err(FrameError::ChunkTooLong(len));
        }
        let end = PAYLOAD_HEADER + len as usize;
        let chunk = payload
            .get(PAYLOAD_HEADER..end)
            .ok_or(FrameError::ShortFrame)?;
        self.buf.extend_from_slice(chunk);

        let more = (flags & FLAG_MORE) != 0;
        if more {
            Ok(Step::NeedMore)
        } else {
            self.done = true;
            Ok(Step::Done)
        }
    }

    /// True once a terminal (non-`more`) frame has been consumed.
    pub fn is_done(&self) -> bool {
        self.done
    }

    /// Consume the assembler and return `(response_data, status_word)` by
    /// splitting the trailing 2-byte ISO-7816 SW off the accumulated buffer
    /// (spec §3, §4.4). Returns `None` if fewer than 2 bytes were collected.
    pub fn into_response(self) -> Option<(Vec<u8>, u16)> {
        if self.buf.len() < 2 {
            return None;
        }
        let split = self.buf.len() - 2;
        let sw = ((self.buf[split] as u16) << 8) | self.buf[split + 1] as u16;
        let mut data = self.buf;
        data.truncate(split);
        Some((data, sw))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_apdu_single_frame() {
        let apdu = [0x80, 0xC5, 0x01, 0x00]; // GET_ECDH_PUBKEY header
        let frames = build_send_frames(&apdu);
        assert_eq!(frames.len(), 1);
        let f = &frames[0];
        assert_eq!(f[0], 0x00); // report id
        assert_eq!(f[1], MAGIC); // single magic byte
        assert_eq!(f[2], FLAG_LAST); // seq 0, last
        assert_eq!(f[3], 4); // chunk len
        assert_eq!(&f[4..8], &apdu);
    }

    #[test]
    fn exactly_61_bytes_is_one_frame() {
        // A 61-byte APDU must fit in a single frame (boundary the earlier bug hit).
        let apdu = vec![0xAA; 61];
        let frames = build_send_frames(&apdu);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0][2], FLAG_LAST); // last, seq 0
        assert_eq!(frames[0][3], 61);
        assert_eq!(&frames[0][4..65], &apdu[..]);
    }

    #[test]
    fn sixty_two_bytes_splits() {
        let apdu = vec![0xAA; 62];
        let frames = build_send_frames(&apdu);
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0][2], FLAG_MORE);
        assert_eq!(frames[0][3], 61);
        assert_eq!(frames[1][2], FLAG_LAST | 1);
        assert_eq!(frames[1][3], 1);
    }

    #[test]
    fn long_apdu_chunks_at_61() {
        let apdu = vec![0xAA; 130]; // -> 61 + 61 + 8
        let frames = build_send_frames(&apdu);
        assert_eq!(frames.len(), 3);
        assert_eq!(frames[0][2], FLAG_MORE);
        assert_eq!(frames[0][3], 61);
        assert_eq!(frames[1][2], FLAG_MORE | 1);
        assert_eq!(frames[1][3], 61);
        assert_eq!(frames[2][2], FLAG_LAST | 2);
        assert_eq!(frames[2][3], 8);
    }

    fn payload(flags_seq: u8, chunk: &[u8]) -> Vec<u8> {
        let mut p = vec![MAGIC, flags_seq, chunk.len() as u8];
        p.extend_from_slice(chunk);
        p.resize(REPORT_PAYLOAD, 0);
        p
    }

    #[test]
    fn assemble_single_frame_with_sw() {
        let mut asm = ResponseAssembler::new();
        let step = asm
            .push(&payload(FLAG_LAST, &[b'A', b'B', 0x90, 0x00]))
            .unwrap();
        assert_eq!(step, Step::Done);
        let (data, sw) = asm.into_response().unwrap();
        assert_eq!(data, b"AB");
        assert_eq!(sw, 0x9000);
    }

    #[test]
    fn assemble_multi_frame() {
        let mut asm = ResponseAssembler::new();
        assert_eq!(
            asm.push(&payload(FLAG_MORE, &[0x01, 0x02])).unwrap(),
            Step::NeedMore
        );
        assert_eq!(
            asm.push(&payload(FLAG_LAST | 1, &[0x03, 0x90, 0x00]))
                .unwrap(),
            Step::Done
        );
        let (data, sw) = asm.into_response().unwrap();
        assert_eq!(data, vec![0x01, 0x02, 0x03]);
        assert_eq!(sw, 0x9000);
    }

    #[test]
    fn busy_frames_dont_advance_sequence() {
        let mut asm = ResponseAssembler::new();
        for i in 1..=3 {
            assert_eq!(
                asm.push(&payload(FLAG_BUSY, &[])).unwrap(),
                Step::Busy { retries: i }
            );
        }
        let step = asm.push(&payload(FLAG_LAST, &[b'Z', 0x90, 0x00])).unwrap();
        assert_eq!(step, Step::Done);
        let (data, sw) = asm.into_response().unwrap();
        assert_eq!(data, b"Z");
        assert_eq!(sw, 0x9000);
    }

    #[test]
    fn bad_magic_rejected() {
        let mut asm = ResponseAssembler::new();
        let mut p = payload(FLAG_LAST, &[0x90, 0x00]);
        p[0] = 0x22; // corrupt magic
        assert_eq!(asm.push(&p), Err(FrameError::BadMagic));
    }

    #[test]
    fn out_of_sequence_rejected() {
        let mut asm = ResponseAssembler::new();
        asm.push(&payload(FLAG_MORE, &[0x01])).unwrap();
        assert_eq!(
            asm.push(&payload(FLAG_LAST | 2, &[0x90, 0x00])),
            Err(FrameError::OutOfSequence {
                expected: 1,
                got: 2
            })
        );
    }

    #[test]
    fn chunk_length_over_61_rejected() {
        let mut asm = ResponseAssembler::new();
        let mut p = vec![MAGIC, FLAG_LAST, 62];
        p.resize(REPORT_PAYLOAD, 0);
        assert_eq!(asm.push(&p), Err(FrameError::ChunkTooLong(62)));
    }
}
