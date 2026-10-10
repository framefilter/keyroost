//! Aegis / 2FAS / otpauth-list auto-detection path — attacker-supplied files.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Dropped-file classification sees raw bytes, text or not.
    let _ = keyroost_import::classify::classify(data, None);
    let _ = keyroost_import::classify::classify(data, Some("dropped.der"));
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = keyroost_import::parse_bulk_any(s);
        let _ = keyroost_import::aegis::is_encrypted(s);
        // The wide parsers read the same attacker-supplied files.
        let _ = keyroost_import::parse_any_wide(s);
        let _ = keyroost_import::parse_list_wide(s);
        let _ = keyroost_import::aegis::parse_wide(s);
        let _ = keyroost_import::twofas::parse_wide(s);
        // Planning any file for any key must not panic either.
        if let Ok(file) = keyroost_import::parse_any_wide(s) {
            plan_everywhere(&file, data);
        }
    }
});

fn plan_everywhere(file: &keyroost_import::ImportFile, data: &[u8]) {
    use keyroost_import::plan::{plan, Existing, OathFamily, Store, StoredName, Target};
    let first_slot = data.first().copied().unwrap_or(0);
    let stores = [
        Store::Molto2,
        Store::Token2Otp,
        Store::Oath(OathFamily::YubiKey { version: None }),
        Store::Oath(OathFamily::YubiKey {
            version: Some((5, 7, 1)),
        }),
        Store::Oath(OathFamily::YubiKey {
            version: Some((4, 3, 0)),
        }),
        Store::Oath(OathFamily::Solo2),
        Store::Oath(OathFamily::Nitrokey3),
        Store::Oath(OathFamily::Other),
    ];
    for store in stores {
        for replace in [false, true] {
            // Plan once against an empty key, then against the key holding
            // everything the first plan named.
            let mut target = Target {
                store,
                first_slot,
                existing: Existing::default(),
                replace,
            };
            let first = plan(file, &target);
            target.existing = Existing {
                names: first
                    .rows
                    .iter()
                    .filter_map(|r| r.name.clone())
                    .collect::<Vec<StoredName>>(),
                hidden: usize::from(first_slot),
            };
            let second = plan(file, &target);
            let _ = (first.counts(), second.counts(), second.writes().count());
            for r in &second.rows {
                if let keyroost_import::plan::Verdict::Skip(s) = &r.verdict {
                    let _ = s.reason(store);
                }
            }
        }
    }
}
