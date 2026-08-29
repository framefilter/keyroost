//! The one place a `--debug` APDU trace line is produced, shared by every
//! transport session (Molto2, PIV, OATH, OpenPGP, ...ProgToken).
//!
//! Two independent consumers, both driven from here:
//!
//! * **The CLI's `--debug` flag** — each session still carries its own
//!   `debug: bool` (set via `set_debug`, exactly as before); when a session
//!   has it on, [`line`] prints straight to stderr, byte-for-byte what the
//!   old scattered `eprintln!` calls produced. That's the only thing that
//!   changed here: every call site used to format and print the line itself;
//!   now it hands the (lazy) line to this one function instead.
//! * **The GUI's activity log** — a front end that wants the exact wire
//!   exchange behind one operation, not a shared stderr stream, calls
//!   [`begin`] before the operation and [`take`] after to collect whatever
//!   was recorded on the calling thread in between — independent of any
//!   session's own `debug` flag, so a session the GUI never told to print
//!   can still be traced. This works because the GUI's blocking device jobs
//!   run to completion on one dedicated worker thread before their result
//!   crosses back to the UI thread (see `keyroost`'s `Worker`), so "recorded
//!   between begin and take" exactly matches "what this one job did".

use std::cell::RefCell;

thread_local! {
    static TRACE: RefCell<Option<Vec<String>>> = const { RefCell::new(None) };
}

/// Start capturing trace lines recorded on this thread. Pairs with [`take`].
/// A capture left open by a panicking job is harmless: the next `begin`
/// simply discards it.
pub fn begin() {
    TRACE.with(|t| *t.borrow_mut() = Some(Vec::new()));
}

/// Stop capturing and return everything recorded since [`begin`]. `None` if
/// no capture is active on this thread.
pub fn take() -> Option<Vec<String>> {
    TRACE.with(|t| t.borrow_mut().take())
}

fn capturing() -> bool {
    TRACE.with(|t| t.borrow().is_some())
}

/// Record one `--debug` trace line. `debug` is the session's own flag: when
/// on, the line prints to stderr immediately, same as always. Independently,
/// if this thread has an active capture, the line is also appended there.
/// `line` is built lazily so the common case — a non-`--debug` CLI run with
/// no GUI capture active — never allocates or formats anything.
pub(crate) fn line(debug: bool, f: impl FnOnce() -> String) {
    if !debug && !capturing() {
        return;
    }
    let s = f();
    if debug {
        eprintln!("{s}");
    }
    TRACE.with(|t| {
        if let Some(buf) = t.borrow_mut().as_mut() {
            buf.push(s);
        }
    });
}
