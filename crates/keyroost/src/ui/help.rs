// crates/keyroost/src/ui/help.rs
//
// Plain-language help content + Learn-link base for the redesign's "?" bubbles.
// Self-contained (no deps). Body copy is lifted verbatim from the prototype and
// is written for non-technical users — keep it that way.
//
// Swap LEARN_BASE for the real github.io site once it's live; every "?" popover
// and the toolbar Learn button derive their URL from it via each topic's slug.

use crate::locales::locales::Translations;

/// Base URL for the Learn / docs site. One line to repoint everything.
pub const LEARN_BASE: &str = "https://framefilter.github.io/keyroost";

/// Full URL for a topic slug (slug already starts with '/', may include '#anchor').
pub fn learn_url(slug: &str) -> String {
    format!("{LEARN_BASE}{slug}")
}

pub struct Help {
    pub title: &'static str,
    pub body: &'static str,
    pub slug: &'static str,
}

/// Look up help content by topic id using translations. Topic ids (use these as the `?` keys):
///   device, fido2, pin, passkeys, oath, pgp, pgp-keys, pgp-card-details, piv,
///   molto, custkey, reset, piv-generate, piv-certificate, piv-import,
///   piv-export, piv-delete, piv-admin
pub fn help(topic: &str, translations: &Translations) -> Option<Help> {
    let title = translations.help_title(topic)?;
    let body = translations.help_body(topic)?;

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

/// Look up help content by topic id (legacy English-only version for compatibility).
pub fn help_english(topic: &str) -> Option<&'static Help> {
    Some(match topic {
        "device" => &Help {
            title: "Your security key",
            body: "A small hardware device that proves it's really you. The secrets it holds are generated on the key and can never be copied off it — so even a compromised computer can't steal them.",
            slug: "/security-keys",
        },
        "fido2" => &Help {
            title: "Passkeys & FIDO2",
            body: "FIDO2 lets this key act as a passkey — a phishing-resistant replacement for passwords. A website remembers your key; you just tap it to sign in. Nothing secret ever leaves the device.",
            slug: "/fido2",
        },
        "pin" => &Help {
            title: "The key's PIN",
            body: "A short PIN that unlocks the key's passkeys on this computer. It is not your account password and never leaves the key. Too many wrong tries and the key locks itself to protect you.",
            slug: "/fido2#pin",
        },
        "passkeys" => &Help {
            title: "Resident passkeys",
            body: "Passkeys stored directly on the key (a.k.a. discoverable credentials). They let you sign in without even typing a username. You can review and remove them here.",
            slug: "/fido2#passkeys",
        },
        "unlock" => &Help {
            title: "Unlocking the key",
            body: "Enter the key's PIN to unlock it for this session. Unlocking gives access to managing passkeys, fingerprints, and security settings; it stays unlocked until you lock it again or unplug the key. The PIN never leaves the device.",
            slug: "",
        },
        "oath" => &Help {
            title: "Authenticator codes (OATH)",
            body: "The rolling 6-digit codes you'd normally get from an authenticator app — but stored on the key itself. They survive a lost or wiped phone and never sync to anyone's cloud.",
            slug: "/oath",
        },
        "otp" => &Help {
            title: "On-device OTP",
            body: "TOTP/HOTP codes stored on this Token2 key's own OTP applet, read over CCID/NFC. Add entries, read live codes, and (on keys that support it) trigger a code by touching the key. The seeds live on the device and never sync anywhere.",
            slug: "/otp",
        },
        "mds" => &Help {
            title: "Device metadata (FIDO MDS)",
            body: "Details the FIDO Alliance publishes about this authenticator model, looked up by its AAGUID: vendor name, icon, certification level (e.g. FIDO Certified L2) and date, supported protocol versions, and more. This data is bundled with keyroost and can be refreshed by a maintainer regenerating it from the FIDO metadata.",
            slug: "/mds",
        },
        "fingerprint" => &Help {
            title: "Fingerprints (biometric enrollment)",
            body: "Enroll, rename, and delete fingerprints on a biometric key via CTAP2 authenticatorBioEnrollment. Enrolled fingerprints let the key satisfy user verification by touch instead of typing the PIN. Requires the PIN to manage. Templates live on the device and never leave it.",
            slug: "/fingerprint",
        },
        "touch-hotp" => &Help {
            title: "HID-HOTP (HOTP-on-touch)",
            body: "Provision a single HOTP slot that types a fresh code as keyboard input when you touch the key outside any session. Needs the keyboard (HID-HOTP) interface enabled. You can change the typing options \u{2014} send Enter, long touch, numeric keypad \u{2014} without re-entering the seed.",
            slug: "/otp#hid-hotp",
        },
        "pgp" => &Help {
            title: "OpenPGP",
            body: "Turns the key into a smart card for encrypting & signing email and files (and for SSH). The private keys live on the card and never touch your computer's disk.",
            slug: "/openpgp",
        },
        "pgp-keys" => &Help {
            title: "Generate or import a key",
            body: "Each of the three keys \u{2014} signature, decryption, authentication \u{2014} can be created right on the card, or imported from an RSA-2048 file you already have. Either way OVERWRITES whatever was in that key, and the only way to clear it again is a full reset. You'll need the admin PIN, and the key may ask for a touch.",
            slug: "/openpgp#keys",
        },
        "pgp-card-details" => &Help {
            title: "Cardholder name & URL",
            body: "Optional labels stored on the card: the cardholder name and a web address where your public key can be found. They're public information, but writing them still needs the admin PIN.",
            slug: "/openpgp#card-details",
        },
        "piv" => &Help {
            title: "PIV smart card",
            body: "A US-government smart-card standard used for enterprise sign-in, VPNs and document signing. Manage it here: generate keys, create self-signed certificates or CA requests (signed on the card), import certificates, change the PIN/PUK and management key, and reset the applet. Writes need the management key (factory default 010203…0708).",
            slug: "/piv",
        },
        "piv-generate" => &Help {
            title: "Generate a key",
            body: "Creates a brand-new private key inside this slot and shows you its public key. If the slot already held a key, this overwrites it for good. You'll need the management key.",
            slug: "/piv#generate",
        },
        "piv-certificate" => &Help {
            title: "Create a certificate",
            body: "A self-signed certificate is stored straight into the slot and is ready to use. A CSR is a request file you send to a certificate authority so they can issue one for you. Either way the signing happens on the card, so it needs the PIN.",
            slug: "/piv#certificate",
        },
        "piv-import" => &Help {
            title: "Import a certificate",
            body: "Loads a certificate file you already have (PEM or DER) into this slot. You'll need the management key.",
            slug: "/piv#import",
        },
        "piv-export" => &Help {
            title: "Export the certificate",
            body: "Saves this slot's certificate to a file on your computer. It's public information, so no PIN is needed.",
            slug: "/piv#export",
        },
        "piv-delete" => &Help {
            title: "Delete from the slot",
            body: "Clearing the certificate leaves the key in place; erasing the private key removes it for good (and needs a YubiKey 5.7 or newer). Both are permanent and can't be undone.",
            slug: "/piv#delete",
        },
        "piv-admin" => &Help {
            title: "Card administration",
            body: "These settings — the PIN and PUK, how many tries they allow, the management key, and a full reset — apply to the whole PIV applet, not to a single slot.",
            slug: "/piv#admin",
        },
        "molto" => &Help {
            title: "Programmable TOTP token",
            body: "A standalone token with its own screen that displays authenticator codes — no phone or app required. You program its slots here, then read the live codes right on the device.",
            slug: "/molto2",
        },
        "custkey" => &Help {
            title: "Customer key",
            body: "An optional password that protects programming on this token. Leave it blank for the factory default. Enter it and Authenticate before writing any slot.",
            slug: "/molto2#customer-key",
        },
        "reset" => &Help {
            title: "Resetting a key",
            body: "A factory reset wipes every credential and PIN on the applet. It cannot be undone — keyroost asks you to type a confirmation and touch the key first.",
            slug: "/reset",
        },
        "settings" => &Help {
            title: "Security policy",
            body: "Change how this key enforces verification and PINs over CTAP 2.1 authenticatorConfig: always require user verification, raise the minimum PIN length, force a PIN change, or enable enterprise attestation. Some of these are one-way and can only be undone by a full reset, so keyroost confirms before applying them.",
            slug: "/settings",
        },
        "large_blobs" => &Help {
            title: "Large blob storage",
            body: "A key-global area where relying parties store opaque, RP-encrypted data (e.g. SSH certificates). Anyone holding the key can read it, so it is not a place for plaintext secrets. keyroost shows each stored entry as hex and ASCII; you can also keep your own plaintext notes here (add, edit, delete). Writing rewrites the whole array with a fresh checksum and needs your PIN. keyroost recognizes its own notes and OpenSSH certificates and shows a capacity meter; anything else is relying-party data, displayed raw and never modified. Any entry can be exported to a file.",
            slug: "/storage",
        },
        _ => return None,
    })
}
