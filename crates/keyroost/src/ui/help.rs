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
///   device, fido2, pin, passkeys, oath, pgp, pgp-keys, pgp-backup, pgp-restore,
///   pgp-expiry, pgp-card-details, piv,
///   molto, custkey, reset, piv-generate, piv-certificate,
///   piv-import-export, piv-delete, piv-test, piv-admin, piv-move, piv-retired
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
            body: "Turns the key into a smart card for encrypting & signing email and files (and for SSH). The card signs and decrypts itself, so the keys can't be read out of it. A key generated on the card never leaves it; keys made with a backup, or imported from a file, also exist in that file.",
            slug: "/openpgp",
        },
        "pgp-keys" => &Help {
            title: "Generate or import a key",
            body: "There are three ways to put keys on the card. Generate on-card: the key is made inside the card and no copy exists, so if the card is lost or reset the key is gone (that matters most for the decryption key, which reads your old messages). Create keys with a backup: all three keys are saved to a passphrase-protected file first. Import from a file: load a key you made elsewhere, such as an RSA file (PEM or DER, 2048 to 4096 bits) or the matching key from an OpenPGP file. Any of them REPLACES what was in that slot, and needs the admin PIN; the card may ask for a touch.",
            slug: "/openpgp#keys",
        },
        "pgp-backup" => &Help {
            title: "Keys with a backup",
            body: "Makes the signature, decryption and authentication keys together, saves them to a backup file that opens only with a passphrase you choose, and loads them onto the card. You also get a public key file to share and a revocation certificate to keep offline (publish it only if the key is lost or stolen). Keep the backup offline, such as on a USB stick in a drawer; if the card is lost, Restore a backup puts the same keys on a new one. Existing files are never overwritten.",
            slug: "/openpgp#backup",
        },
        "pgp-restore" => &Help {
            title: "Restore a backup",
            body: "Loads keys from a backup file onto this card: one keyroost saved, or one exported from GnuPG. You choose which of the keys to load; each REPLACES the key in its slot. You'll need the backup's passphrase and the card's admin PIN. A wrong passphrase, an unreadable file or a key type the card doesn't list is caught before anything is written, so the card stays as it was. If loading fails after the card began replacing a key, keyroost names that slot: its old key may be gone.",
            slug: "/openpgp#backup",
        },
        "pgp-expiry" => &Help {
            title: "Change expiry date",
            body: "Moves the expiry date of your public key. Choose Never, 1, 2, 3 or 5 years, or a date; a date expires at midday (UTC) on that day, as in GnuPG. Sign the change with this card (user PIN) or with the backup (its passphrase), then share the updated public key file again so others see the new date. The keys themselves stay the same.",
            slug: "/openpgp#expiry",
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
            body: "A self-signed certificate is stored straight into the slot and is ready to use. A CSR is a request file you send to a certificate authority so they can issue one for you. Either way the signing happens on the card, so it needs the PIN; for a CSR, keyroost first asks where to save the request file. Key usage is optional: left at Undefined, no key usage extension is written. It starts out set to the PIV standard's value for the slot (Undefined where the standard defines none), and you can select multiple usages.",
            slug: "/piv#certificate",
        },
        "piv-import-export" => &Help {
            title: "Import or export a certificate",
            body: "Import loads a certificate file you already have (PEM or DER) into this slot — keyroost asks you to pick the file, then needs the management key. Export saves this slot's certificate to a file — keyroost asks where to write it; it's public information, so no PIN is needed.",
            slug: "/piv#import",
        },
        "piv-move" => &Help {
            title: "Move a key",
            body: "Relocates this slot's private key into another slot without it ever leaving the card — useful for retiring a decryption key so old mail stays readable while a fresh key takes over. Nothing is destroyed: keyroost refuses if the destination already holds a key, and the certificate stays behind in the original slot. Needs the management key and a YubiKey 5.7 or newer.",
            slug: "/piv#move-key",
        },
        "piv-retired" => &Help {
            title: "Retired slots",
            body: "Twenty extra slots (82–95) that hold decryption keys you've rotated out, so mail and files encrypted to an old key can still be opened. They work like the four main slots but are read only when you open this section, because checking them means asking the card about each one in turn.",
            slug: "/piv#retired",
        },
        "piv-delete" => &Help {
            title: "Delete from the slot",
            body: "Clearing the certificate leaves the key in place; erasing the private key removes it for good (and needs a YubiKey 5.7 or newer). Both are permanent and can't be undone.",
            slug: "/piv#delete",
        },
        "piv-test" => &Help {
            title: "Test the slot's key",
            body: "Checks that the slot's private key actually works: keyroost builds a small fixed challenge from the slot certificate's public key, has the card run every operation the key type supports (decrypt for RSA; key-agree for ECDH curves; sign for RSA / ECDSA / Ed25519), and verifies each result against that same public key. It reports each operation's pass or fail. It needs the PIN unless the slot's PIN policy is \u{201c}never\u{201d}, and it changes nothing on the card.",
            slug: "/piv#test",
        },
        "piv-admin" => &Help {
            title: "Card administration",
            body: "These settings — the PIN and PUK, how many tries they allow, the management key, a full reset, and the card's CHUID — apply to the whole PIV applet, not to a single slot.",
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
