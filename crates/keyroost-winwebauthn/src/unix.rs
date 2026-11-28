//! Unix implementation of [`crate::erase_on_interrupt`]: a SIGINT/SIGTERM
//! handler, installed only while the CLI shows a password, that puts the
//! terminal settings back, writes the erase and ends the process by the
//! same signal, so a parent sees it killed as it would have been.
//!
//! All of this crate's Unix FFI is confined here. The handler calls only
//! async-signal-safe functions (`tcsetattr`, `write`, `sigaction`,
//! `sigemptyset`, `sigaddset`, `sigprocmask`, `raise`, `_exit`), never
//! reads `errno`, and reads only atomics and memory written before it was
//! armed. Both signals are blocked while it runs, so a second one can't
//! end the process before the erase is written.

use std::cell::UnsafeCell;
use std::fs::File;
use std::mem::MaybeUninit;
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicPtr, AtomicUsize, Ordering};

/// The signals the guard answers: Ctrl+C (which the password reader turns
/// into a `SIGINT` of its own) and a plain `kill`.
pub(crate) const SIGNALS: [libc::c_int; 2] = [libc::SIGINT, libc::SIGTERM];

/// The terminal settings saved before the password reader changed them.
struct Saved(UnsafeCell<MaybeUninit<libc::termios>>);

// SAFETY: written only by `arm` before `ARMED` is set (Release) and read
// only by the handler after it sees `ARMED` (Acquire); one guard at a time.
unsafe impl Sync for Saved {}

static SAVED: Saved = Saved(UnsafeCell::new(MaybeUninit::uninit()));
/// The terminal's descriptor the settings go back to; -1 for none.
static TTY_FD: AtomicI32 = AtomicI32::new(-1);
static ERASE_PTR: AtomicPtr<u8> = AtomicPtr::new(std::ptr::null_mut());
static ERASE_LEN: AtomicUsize = AtomicUsize::new(0);
static NOTE_PTR: AtomicPtr<u8> = AtomicPtr::new(std::ptr::null_mut());
static NOTE_LEN: AtomicUsize = AtomicUsize::new(0);
static ARMED: AtomicBool = AtomicBool::new(false);

/// The exit status of a process ended by `sig`, as a shell reports it:
/// the handler's fallback if re-raising the signal doesn't end it.
pub(crate) fn interrupted_status(sig: libc::c_int) -> libc::c_int {
    128 + sig
}

/// How many failed `write(2)` calls [`write_all`] tries again (an `EINTR`
/// from a signal outside the blocked pair, say) before giving up; it never
/// reads `errno` to tell why.
const WRITE_RETRIES: u32 = 8;

/// `write(2)` all of `ptr`/`len` to `fd`, trying a failed call again a
/// few times.
///
/// # Safety
/// `ptr`/`len` describe a live buffer (here: a `&'static str`), or are
/// null/0.
unsafe fn write_all(fd: libc::c_int, mut ptr: *const u8, mut len: usize) {
    let mut retries = WRITE_RETRIES;
    while !ptr.is_null() && len > 0 {
        // SAFETY: the caller's buffer holds `len` more bytes from `ptr`.
        let n = unsafe { libc::write(fd, ptr.cast(), len) };
        if n > 0 {
            let n = n as usize;
            // SAFETY: `n <= len`, so this stays inside the buffer.
            ptr = unsafe { ptr.add(n) };
            len -= n;
        } else if n < 0 && retries > 0 {
            retries -= 1;
        } else {
            return;
        }
    }
}

/// The set holding both [`SIGNALS`]: blocked while the handler runs.
///
/// # Safety
/// `set` is a live `sigset_t`.
unsafe fn both_signals(set: *mut libc::sigset_t) {
    // SAFETY: the caller's set is live.
    unsafe {
        libc::sigemptyset(set);
        for sig in SIGNALS {
            libc::sigaddset(set, sig);
        }
    }
}

extern "C" fn on_signal(sig: libc::c_int) {
    if ARMED.swap(false, Ordering::AcqRel) {
        let fd = TTY_FD.load(Ordering::Acquire);
        // SAFETY: SAVED was written before ARMED was set when `fd` is a
        // descriptor; the erase and note pointers are 'static strings.
        unsafe {
            if fd >= 0 {
                libc::tcsetattr(fd, libc::TCSANOW, (*SAVED.0.get()).as_ptr());
            }
            write_all(
                libc::STDOUT_FILENO,
                ERASE_PTR.load(Ordering::Acquire),
                ERASE_LEN.load(Ordering::Acquire),
            );
            write_all(
                libc::STDERR_FILENO,
                NOTE_PTR.load(Ordering::Acquire),
                NOTE_LEN.load(Ordering::Acquire),
            );
        }
    }
    // SAFETY: the default action back, `sig` unblocked (it is blocked
    // while its handler runs) and raised again: the process ends by the
    // signal, as it would have without the handler. Should it not, the
    // shell's status for it. All locals are live.
    unsafe {
        let mut default: libc::sigaction = std::mem::zeroed();
        default.sa_sigaction = libc::SIG_DFL;
        libc::sigemptyset(&mut default.sa_mask);
        libc::sigaction(sig, &default, std::ptr::null_mut());
        let mut only: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut only);
        libc::sigaddset(&mut only, sig);
        libc::sigprocmask(libc::SIG_UNBLOCK, &only, std::ptr::null_mut());
        libc::raise(sig);
        libc::_exit(interrupted_status(sig))
    }
}

/// The armed handler; dropping it puts the previous handlers back.
pub(crate) struct Guard {
    previous: [libc::sigaction; 2],
    /// Kept open so the handler's descriptor stays valid.
    _tty: Option<File>,
}

/// Arm the handler: the terminal's settings (from `/dev/tty`, when it
/// opens) saved for it to put back, `erase` and `note` for it to write.
/// `None` when a guard is already held or a handler can't be installed.
pub(crate) fn arm(erase: &'static str, note: &'static str) -> Option<Guard> {
    if ARMED.load(Ordering::Acquire) {
        return None;
    }
    let tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .ok();
    let fd = tty.as_ref().map_or(-1, AsRawFd::as_raw_fd);
    // SAFETY: tcgetattr writes one termios through the pointer, into the
    // static no handler reads until ARMED is set below.
    let saved = fd >= 0 && unsafe { libc::tcgetattr(fd, (*SAVED.0.get()).as_mut_ptr()) } == 0;
    TTY_FD.store(if saved { fd } else { -1 }, Ordering::Release);
    ERASE_PTR.store(erase.as_ptr().cast_mut(), Ordering::Release);
    ERASE_LEN.store(erase.len(), Ordering::Release);
    NOTE_PTR.store(note.as_ptr().cast_mut(), Ordering::Release);
    NOTE_LEN.store(note.len(), Ordering::Release);
    ARMED.store(true, Ordering::Release);

    // SAFETY: zeroed is a valid `sigaction` (no handler, empty flags);
    // the set calls and sigaction take pointers to live locals.
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t;
        both_signals(&mut action.sa_mask);
        let mut previous: [libc::sigaction; 2] = std::mem::zeroed();
        for (i, sig) in SIGNALS.iter().enumerate() {
            if libc::sigaction(*sig, &action, &mut previous[i]) != 0 {
                for (j, s) in SIGNALS.iter().enumerate().take(i) {
                    libc::sigaction(*s, &previous[j], std::ptr::null_mut());
                }
                ARMED.store(false, Ordering::Release);
                TTY_FD.store(-1, Ordering::Release);
                return None;
            }
        }
        Some(Guard {
            previous,
            _tty: tty,
        })
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        // SAFETY: puts back the actions `arm` saved, from live memory.
        unsafe {
            for (sig, prev) in SIGNALS.iter().zip(&self.previous) {
                libc::sigaction(*sig, prev, std::ptr::null_mut());
            }
        }
        ARMED.store(false, Ordering::Release);
        TTY_FD.store(-1, Ordering::Release);
    }
}

/// The handler currently installed for `sig` (for the tests).
#[cfg(test)]
pub(crate) fn current_handler(sig: libc::c_int) -> libc::sighandler_t {
    // SAFETY: a null new action only reads the current one into a local.
    unsafe {
        let mut now: libc::sigaction = std::mem::zeroed();
        libc::sigaction(sig, std::ptr::null(), &mut now);
        now.sa_sigaction
    }
}

/// Whether `sig` is in the handler's mask (for the tests).
#[cfg(test)]
pub(crate) fn masks(sig: libc::c_int) -> bool {
    // SAFETY: a null new action only reads the current one into a local.
    unsafe {
        let mut now: libc::sigaction = std::mem::zeroed();
        libc::sigaction(libc::SIGINT, std::ptr::null(), &mut now);
        libc::sigismember(&now.sa_mask, sig) == 1
    }
}

/// Whether the guard is armed (for the tests).
#[cfg(test)]
pub(crate) fn armed() -> bool {
    ARMED.load(Ordering::Acquire)
}

/// The handler `arm` installs (for the tests).
#[cfg(test)]
pub(crate) fn handler() -> libc::sighandler_t {
    on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t
}
