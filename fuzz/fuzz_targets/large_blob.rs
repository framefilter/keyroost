//! Large-blob array parser — fed the serialized array a FIDO key returns,
//! which any tool (or a hostile key) may have written. Beyond not panicking,
//! a parsed array must survive a rewrite: serialize it, parse it back, and the
//! same entries (byte for byte) and skipped elements come back in the same
//! order. Looking up the key's name and classifying every entry must not
//! panic either. An array read with bytes after its end refuses to be rewritten.
#![no_main]
use keyroost_ctap::large_blobs::LargeBlobArray;
use libfuzzer_sys::fuzz_target;

const CHECKSUM_LEN: usize = 16;

fuzz_target!(|data: &[u8]| {
    let Ok(array) = LargeBlobArray::parse(data) else {
        return;
    };
    // Hostile entries must not panic the name lookup or the classifier
    // (which trial-decrypts every entry under the published name key).
    let _ = array.label();
    for entry in array.entries() {
        let _ = entry.classify();
    }
    // Bytes after the array can't survive a rewrite, so it is refused.
    let Ok(serialized) = array.serialize_with_checksum() else {
        return;
    };
    let body = &serialized[..serialized.len() - CHECKSUM_LEN];
    let again = LargeBlobArray::parse(body).expect("a serialized array parses back");
    // Entries compare with the bytes they were read as, so an entry whose
    // unknown keys were dropped (or whose encoding changed) fails here.
    assert_eq!(array.entries(), again.entries());
    assert_eq!(array.skipped_count(), again.skipped_count());
    // Same elements in the same order: re-serializing changes nothing.
    assert_eq!(again.serialize_with_checksum().ok(), Some(serialized));
});
