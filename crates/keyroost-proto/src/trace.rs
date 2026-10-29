//! The one `--debug` trace line format shared by every keyroost crate. Not a
//! stable contract: the text may change between releases.
//!
//! Also the one place a trace line goes once built ([`emit`]): to stderr when
//! the caller's own `--debug` switch is on, and into this thread's capture
//! when a front end opened one with [`begin`]. The GUI's activity log opens a
//! capture around each device job (they run to completion on one worker
//! thread) and collects it with [`take`], so every transport — smart-card
//! applets, CTAP over USB and over a reader — lands in the same log.

use std::cell::RefCell;

thread_local! {
    static CAPTURE: RefCell<Option<Vec<String>>> = const { RefCell::new(None) };
}

/// Start capturing trace lines emitted on this thread. Pairs with [`take`].
/// A capture left open by a panicking job is harmless: the next `begin`
/// simply discards it.
pub fn begin() {
    CAPTURE.with(|t| *t.borrow_mut() = Some(Vec::new()));
}

/// Stop capturing and return everything emitted since [`begin`]. `None` if
/// no capture is active on this thread.
pub fn take() -> Option<Vec<String>> {
    CAPTURE.with(|t| t.borrow_mut().take())
}

/// True while a capture is open on this thread.
#[must_use]
pub fn capturing() -> bool {
    CAPTURE.with(|t| t.borrow().is_some())
}

/// Emit one trace line: printed to stderr when `print` (the caller's
/// `--debug` switch), and appended to this thread's capture when one is
/// open. Built lazily, so the common case — no `--debug`, no capture — never
/// formats anything.
pub fn emit(print: bool, line: impl FnOnce() -> String) {
    if !print && !capturing() {
        return;
    }
    let s = line();
    if print {
        eprintln!("{s}");
    }
    CAPTURE.with(|t| {
        if let Some(buf) = t.borrow_mut().as_mut() {
            buf.push(s);
        }
    });
}

/// Width the label column is padded to (longer labels push the body right).
pub const LABEL_WIDTH: usize = 20;

/// Which way a trace line points.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dir {
    /// `>` — bytes sent to the device.
    Sent,
    /// `<` — bytes received from the device.
    Received,
    /// `!` — a note about what keyroost decided.
    Note,
}

impl Dir {
    /// The one-character marker that starts a line in this direction.
    #[must_use]
    pub const fn symbol(self) -> char {
        match self {
            Dir::Sent => '>',
            Dir::Received => '<',
            Dir::Note => '!',
        }
    }
}

/// A serial-like value shortened for a trace: the first and last two
/// characters plus the length (`12…78 (len 8)`), so pasted `--debug` output
/// never carries the whole value. Values of four characters or fewer are shown
/// as is.
#[must_use]
pub fn abbreviate(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    if chars.len() <= 4 {
        return value.to_string();
    }
    let head: String = chars[..2].iter().collect();
    let tail: String = chars[chars.len() - 2..].iter().collect();
    format!("{head}\u{2026}{tail} (len {})", chars.len())
}

/// A smart-card reader's name for a trace. Some systems put the device's USB
/// serial in parentheses in the name ("Solo 2 [CCID/ICCD Interface]
/// (07A9…) 01 00"); that part is shortened like [`abbreviate`]. A short
/// parenthesized product ID ("Security Key(0024)") and names without one come
/// back unchanged.
#[must_use]
pub fn reader_name(name: &str) -> String {
    let (Some(open), Some(close)) = (name.find('('), name.rfind(')')) else {
        return name.to_string();
    };
    let Some(inner) = name.get(open + 1..close) else {
        return name.to_string();
    };
    if inner.len() <= 4 || !inner.chars().all(|c| c.is_ascii_alphanumeric()) {
        return name.to_string();
    }
    format!(
        "{}({}){}",
        &name[..open],
        abbreviate(inner),
        &name[close + 1..]
    )
}

/// `"> label                body"`, with no trailing whitespace.
#[must_use]
pub fn format_line(dir: Dir, label: &str, body: &str) -> String {
    let line = format!(
        "{} {:<width$}  {}",
        dir.symbol(),
        label,
        body,
        width = LABEL_WIDTH
    );
    line.trim_end().to_string()
}

#[cfg(test)]
mod tests {
    use super::{abbreviate, begin, emit, format_line, reader_name, take, Dir, LABEL_WIDTH};

    /// A serial some systems put in a reader's name is shortened; a short
    /// parenthesized product ID and names without one stay as they are.
    #[test]
    fn reader_name_shortens_a_serial_in_parentheses() {
        assert_eq!(
            reader_name("SoloKeys Solo 2 [CCID/ICCD Interface] (07A9568FBE31AD5D) 01 00"),
            "SoloKeys Solo 2 [CCID/ICCD Interface] (07\u{2026}5D (len 16)) 01 00"
        );
        assert_eq!(
            reader_name("TOKEN2 FIDO2 Security Key(0024) 0"),
            "TOKEN2 FIDO2 Security Key(0024) 0"
        );
        assert_eq!(
            reader_name("Yubico YubiKey OTP+FIDO+CCID 00 00"),
            "Yubico YubiKey OTP+FIDO+CCID 00 00"
        );
        assert_eq!(reader_name("odd (with spaces) 00"), "odd (with spaces) 00");
    }

    /// A capture collects every line emitted on this thread between `begin`
    /// and `take`, printed or not; with no capture and nothing to print, the
    /// line is never built.
    #[test]
    fn a_capture_collects_what_this_thread_emits() {
        assert_eq!(take(), None);
        emit(false, || unreachable!("built with no capture and no print"));
        begin();
        emit(false, || "> a".to_string());
        emit(false, || "< b".to_string());
        assert_eq!(take(), Some(vec!["> a".to_string(), "< b".to_string()]));
        assert_eq!(take(), None);
        // Another thread's lines stay out of this thread's capture.
        begin();
        std::thread::spawn(|| emit(false, || "elsewhere".to_string()))
            .join()
            .unwrap();
        assert_eq!(take(), Some(Vec::new()));
    }

    #[test]
    fn abbreviate_keeps_two_each_end_plus_length() {
        assert_eq!(abbreviate("12345678"), "12\u{2026}78 (len 8)");
        assert_eq!(abbreviate("12345"), "12\u{2026}45 (len 5)");
        assert_eq!(abbreviate("1234"), "1234");
        assert_eq!(abbreviate(""), "");
    }

    #[test]
    fn format_line_grammar() {
        assert_eq!(
            format_line(Dir::Sent, "select piv", "00 a4 04 00"),
            "> select piv            00 a4 04 00"
        );
        assert_eq!(
            format_line(Dir::Received, "select piv", "90 00"),
            "< select piv            90 00"
        );
        assert_eq!(format_line(Dir::Note, "piv mgmt-key", ""), "! piv mgmt-key");
        assert!(format_line(Dir::Sent, "get info (serial + time)", "80 41")
            .starts_with("> get info (serial + time)  80 41"));
        for d in [Dir::Sent, Dir::Received, Dir::Note] {
            assert_eq!(
                format_line(d, "x", "y").chars().nth(2 + LABEL_WIDTH + 2),
                Some('y')
            );
        }
    }
}
