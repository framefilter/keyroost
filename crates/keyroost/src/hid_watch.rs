//! FIDO HID hotplug detection for keys that have no smart-card reader.
//!
//! The PC/SC [`keyroost_transport::ReaderWatcher`] only sees readers, so a
//! FIDO-only key (no CCID interface) plugged in or pulled after startup went
//! unnoticed until a manual Refresh. This watcher lists the FIDO HID devices
//! every [`POLL_INTERVAL`] and calls back when the set of device paths
//! changes; the app then runs the same rescan burst a reader hotplug starts,
//! with the same hold-offs (armed reset, busy worker, open rename field).
//!
//! Enumeration only — no device is ever opened here. On Linux that is a sysfs
//! read; elsewhere a hidapi enumeration (on Windows without admin rights it
//! may list no FIDO devices at all, which simply means no events).

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// How often the FIDO HID device list is re-read.
const POLL_INTERVAL: Duration = Duration::from_millis(1500);

/// Sleep granularity, so a dropped watcher joins promptly on exit.
const SLICE: Duration = Duration::from_millis(250);

/// A background thread that calls `on_change` when a FIDO HID device appears
/// or disappears. Stops and joins its thread when dropped.
pub struct HidWatcher {
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl HidWatcher {
    /// Spawn the watcher. `None` when this build has no HID backend or the
    /// thread can't start — the app then falls back to manual rescans.
    /// `on_change` runs on the watcher thread, so it must be cheap (set a
    /// flag, request a repaint).
    pub fn spawn<F>(on_change: F) -> Option<Self>
    where
        F: Fn() + Send + 'static,
    {
        if !keyroost_hid::hid_supported() {
            return None;
        }
        let stop = Arc::new(AtomicBool::new(false));
        let stop_thread = stop.clone();
        let handle = std::thread::Builder::new()
            .name("keyroost-hid-watch".into())
            .spawn(move || {
                let mut last = fido_paths().unwrap_or_default();
                while !stop_thread.load(Ordering::Relaxed) {
                    let mut slept = Duration::ZERO;
                    while slept < POLL_INTERVAL && !stop_thread.load(Ordering::Relaxed) {
                        std::thread::sleep(SLICE);
                        slept += SLICE;
                    }
                    if stop_thread.load(Ordering::Relaxed) {
                        break;
                    }
                    // A failed enumeration says nothing about hotplug; keep
                    // the last good list and try again next round.
                    let Some(now) = fido_paths() else {
                        continue;
                    };
                    if hid_set_changed(&last, &now) {
                        on_change();
                        last = now;
                    }
                }
            })
            .inspect_err(|e| {
                eprintln!(
                    "warning: could not start the FIDO key hot-plug watcher ({e}); keys without \
                     a smart-card interface will appear only after Refresh this session"
                );
            })
            .ok()?;
        Some(HidWatcher {
            stop,
            handle: Some(handle),
        })
    }
}

impl Drop for HidWatcher {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

/// The paths of the FIDO HID devices present now, or `None` if enumeration
/// failed.
fn fido_paths() -> Option<Vec<PathBuf>> {
    let devices = keyroost_hid::enumerate().ok()?;
    Some(
        devices
            .into_iter()
            .filter(keyroost_hid::HidDevice::is_fido)
            .map(|d| d.path)
            .collect(),
    )
}

/// Whether two FIDO device-path lists name a different set of devices. Order
/// and duplicates (hidapi can list one path per top-level collection) don't
/// count as a change.
fn hid_set_changed(last: &[PathBuf], now: &[PathBuf]) -> bool {
    use std::collections::BTreeSet;
    let a: BTreeSet<&PathBuf> = last.iter().collect();
    let b: BTreeSet<&PathBuf> = now.iter().collect();
    a != b
}

#[cfg(test)]
mod tests {
    use super::hid_set_changed;
    use std::path::PathBuf;

    fn paths(list: &[&str]) -> Vec<PathBuf> {
        list.iter().map(PathBuf::from).collect()
    }

    #[test]
    fn unchanged_set_is_no_change() {
        assert!(!hid_set_changed(&paths(&[]), &paths(&[])));
        assert!(!hid_set_changed(
            &paths(&["/dev/hidraw3"]),
            &paths(&["/dev/hidraw3"])
        ));
    }

    #[test]
    fn order_and_duplicates_are_no_change() {
        assert!(!hid_set_changed(
            &paths(&["/dev/hidraw3", "/dev/hidraw5"]),
            &paths(&["/dev/hidraw5", "/dev/hidraw3", "/dev/hidraw5"])
        ));
    }

    #[test]
    fn plugging_or_pulling_a_key_is_a_change() {
        assert!(hid_set_changed(&paths(&[]), &paths(&["/dev/hidraw3"])));
        assert!(hid_set_changed(&paths(&["/dev/hidraw3"]), &paths(&[])));
        assert!(hid_set_changed(
            &paths(&["/dev/hidraw3"]),
            &paths(&["/dev/hidraw3", "/dev/hidraw7"])
        ));
    }

    #[test]
    fn a_replug_onto_a_new_path_is_a_change() {
        assert!(hid_set_changed(
            &paths(&["/dev/hidraw3"]),
            &paths(&["/dev/hidraw4"])
        ));
    }
}
