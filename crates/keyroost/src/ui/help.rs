// crates/keyroost/src/ui/help.rs
//
// Plain-language help content + Learn-link base for the redesign's "?" bubbles.
// Self-contained (no deps). Body copy is lifted verbatim from the prototype and
// is written for non-technical users — keep it that way.
//
// Swap LEARN_BASE for the real github.io site once it's live; every "?" popover
// and the toolbar Learn button derive their URL from it via each topic's slug.

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

/// Look up help content by topic id. Topic ids (use these as the `?` keys):
///   device, fido2, pin, passkeys, oath, pgp, piv, molto, custkey, reset
pub fn help(topic: &str) -> Option<&'static Help> {
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
            body: "Enroll, rename, and delete fingerprints on a biometric Token2 key via CTAP2 authenticatorBioEnrollment. Enrolled fingerprints let the key satisfy user verification by touch instead of typing the PIN. Requires the PIN to manage. Templates live on the device and never leave it.",
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
        "piv" => &Help {
            title: "PIV smart card",
            body: "A US-government smart-card standard used for enterprise sign-in, VPNs and document signing. Manage it here: generate keys, create self-signed certificates or CA requests (signed on the card), import certificates, change the PIN/PUK and management key, and reset the applet. Writes need the management key (factory default 010203…0708).",
            slug: "/piv",
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
        _ => return None,
    })
}
