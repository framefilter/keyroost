//! The one `--debug` trace line format shared by every keyroost crate. Not a
//! stable contract: the text may change between releases.

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
    use super::{format_line, Dir, LABEL_WIDTH};

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
