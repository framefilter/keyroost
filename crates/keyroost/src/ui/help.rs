// crates/keyroost/src/ui/help.rs
//
// Plain-language help content + Learn-link base for the redesign's "?" bubbles.
// Self-contained (no deps). Body copy is lifted verbatim from the prototype and
// is written for non-technical users — keep it that way.
//
// Swap LEARN_BASE for the real github.io site once it's live; every "?" popover
// and the toolbar Learn button derive their URL from it via each topic's slug.

use crate::locales::Translations;

/// Base URL for the Learn / docs site. One line to repoint everything.
pub const LEARN_BASE: &str = "https://framefilter.github.io/keyroost";

/// Full URL for a topic slug (slug already starts with '/', may include '#anchor').
pub fn learn_url(slug: &str) -> String {
    format!("{LEARN_BASE}{slug}")
}

pub struct Help {
    pub title: String,
    pub body: String,
    pub slug: &'static str,
}

/// Look up help content by topic id using translations. Topic ids (use these as the `?` keys):
///   device, fido2, pin, passkeys, oath, pgp, pgp-keys, pgp-card-details, piv,
///   molto, custkey, reset, piv-generate, piv-certificate, piv-import,
///   piv-export, piv-delete, piv-admin
pub fn help(topic: &str, translations: &Translations) -> Option<Help> {
    let title = translations.help_title(topic)?.to_string();
    let body = translations.help_body(topic)?.to_string();

    // Static slugs for each topic
    let slug = match topic {
        "device" => "/security-keys",
        "fido2" => "/fido2",
        "pin" => "/fido2#pin",
        "passkeys" => "/fido2#passkeys",
        "unlock" => "",
        "oath" => "/oath",
        "otp" => "/otp",
        "mds" => "/mds",
        "fingerprint" => "/fingerprint",
        "touch-hotp" => "/otp#hid-hotp",
        "pgp" => "/openpgp",
        "pgp-keys" => "/openpgp#keys",
        "pgp-card-details" => "/openpgp#card-details",
        "piv" => "/piv",
        "piv-generate" => "/piv#generate",
        "piv-certificate" => "/piv#certificate",
        "piv-import" => "/piv#import",
        "piv-export" => "/piv#export",
        "piv-delete" => "/piv#delete",
        "piv-admin" => "/piv#admin",
        "molto" => "/molto2",
        "custkey" => "/molto2#customer-key",
        "reset" => "/reset",
        "settings" => "/settings",
        "large_blobs" => "/storage",
        _ => return None,
    };

    Some(Help {
        title,
        body,
        slug,
    })
}
