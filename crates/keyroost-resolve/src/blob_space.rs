//! How full a key's FIDO2 large-blob store is, as the CLI and the app both
//! say it after a write.
//!
//! The store is shared space on the key: websites keep data there with
//! their passkeys, next to keyroost's vaults, notes and the key's own name.
//! A write that leaves little room is never refused for it; the front ends
//! print [`store_note`] after it instead.

use keyroost_ctap::large_blobs::BlobCapacity;

/// A write that leaves less than 1/`STORE_NOTE_DIVISOR` of the store free
/// gets [`store_note`].
pub const STORE_NOTE_DIVISOR: u64 = 4;

/// The note shown after a write to the large-blob store (a vault, a note,
/// the key's name) when less than a quarter of it is free, with the numbers
/// `fido vault list` prints; `None` while there is room, and for a key that
/// reports no store. Starts lowercase, for the CLI's `note: ` prefix.
pub fn store_note(cap: &BlobCapacity) -> Option<String> {
    if cap.max_bytes == 0 || cap.free_bytes >= cap.max_bytes / STORE_NOTE_DIVISOR {
        return None;
    }
    let percent = cap.used_bytes.min(cap.max_bytes) * 100 / cap.max_bytes;
    Some(format!(
        "the key's large-blob store is {percent}% full ({} of {} bytes). \
         Websites that store data with their passkeys may have no room left.",
        cap.used_bytes, cap.max_bytes
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_note_shows_once_less_than_a_quarter_is_free() {
        let store = |used: u64| BlobCapacity {
            max_bytes: 4096,
            used_bytes: used,
            free_bytes: 4096 - used,
            entry_count: 3,
        };
        // 1024 free is exactly a quarter: no note yet.
        assert_eq!(store_note(&store(3072)), None);
        assert_eq!(store_note(&store(300)), None);
        // 1023 free: the note.
        assert_eq!(
            store_note(&store(3073)).as_deref(),
            Some(
                "the key's large-blob store is 75% full (3073 of 4096 bytes). \
                 Websites that store data with their passkeys may have no room left."
            )
        );
        assert_eq!(
            store_note(&store(3360)).as_deref(),
            Some(
                "the key's large-blob store is 82% full (3360 of 4096 bytes). \
                 Websites that store data with their passkeys may have no room left."
            )
        );
        let full = store_note(&store(4096)).unwrap();
        assert!(full.contains("100% full (4096 of 4096 bytes)"), "{full}");
        // A key that reports no store never gets the note.
        let none = BlobCapacity {
            max_bytes: 0,
            used_bytes: 0,
            free_bytes: 0,
            entry_count: 0,
        };
        assert_eq!(store_note(&none), None);
    }
}
