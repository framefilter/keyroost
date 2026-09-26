//! Fingerprinting a PIV applet from its ATR/ATS historical bytes, its SELECT
//! response, and — for a couple of identities — a live probe of whether a
//! specific applet can be selected by AID at all ([`FEITIAN_RID`],
//! [`SWISSBIT_RID`]). Whether the card answers a particular instruction
//! is an equally valid fingerprinting signal this module's shape
//! accommodates the same way, even though no identity currently decides on
//! that alone. Best-effort, vendor-fingerprinting logic layered on top of the
//! plain PIV byte layer. Pure and I/O-free, like the rest of this crate:
//! [`atr_identity`] and [`select_identity`] turn raw bytes the transport
//! layer already has into short fingerprinting strings, and [`classify`]
//! turns those strings (plus the live-probe bits the transport layer
//! supplies) into an [`AppletFingerprint`].
//!
//! This is fingerprinting, not a protocol the spec defines — every rule here
//! is inferred from what a particular vendor's implementation happens to put
//! in a particular field, answer to a command, or expose as a selectable
//! applet, so a card this doesn't recognize just reports
//! [`AppletFingerprint::Generic`] rather than erroring.

/// Feitian Technologies' registered RID (Registered Application Provider
/// Identifier — the 5-byte ISO 7816-5 prefix common to every AID Feitian
/// registers under) — see
/// <https://qccdata.qichacha.com/Disclosure/f31b9be6f9eb76113e9c078f7f375997.pdf>
/// for the source associating this RID with Feitian.
/// [`AppletFingerprint::Feitian`] is recognised solely by whether the card
/// accepts a SELECT for this RID on its own (no PIX) — the transport layer
/// SELECTs it (then re-SELECTs PIV) only when nothing else already
/// fingerprinted the applet, since this is the lowest-priority, catch-all
/// criterion and every other one is cheaper to check first.
pub const FEITIAN_RID: [u8; 5] = [0xD1, 0x56, 0x00, 0x01, 0x32];

/// An obscure second PIV applet instance some Gemalto/Thales IDPrime cards
/// register under, alongside the standard PIV AID — see
/// <https://blog.rchapman.org/posts/Smart_card_installing_Hello_World_on_a_Gemalto_IDPrime_PIV_2.0_card>.
/// [`AppletFingerprint::IdPrime`] is recognised solely by whether the card
/// accepts a SELECT for this AID (`SW = 9000` or the non-standard `SW =
/// 6999`) — the transport layer SELECTs it (then re-SELECTs PIV) only when
/// nothing else, not even [`FEITIAN_RID`], already fingerprinted the applet,
/// since this is the lowest-priority, catch-all criterion and every other
/// one is cheaper to check first.
pub const IDPRIME_SECONDARY_PIV_AID: [u8; 11] = [
    0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x02, 0x00,
];

/// Trussed's admin application AID. On a Nitrokey
/// ([`AppletFingerprint::Trussed`]`(`[`TrussedVariant::NitroKey`]`)`), its
/// firmware version ([`NITROKEY_GET_VERSION_STRING`]) and hardware variant
/// ([`NITROKEY_GET_ADMIN_STATUS`]) are read through this application's
/// management commands rather than anything PIV-specific.
pub const NITROKEY_ADMIN_AID: [u8; 9] = [0xA0, 0x00, 0x00, 0x08, 0x47, 0x00, 0x00, 0x00, 0x01];

/// Trussed/Nitrokey admin application management command: `GET STATUS`
/// (`INS 0x80`), a bare case-1 APDU (no data, no `Le`) answering with a
/// 5-byte status structure — see [`parse_nitrokey_variant`] for the one byte
/// this crate reads out of it. Only meaningful once [`NITROKEY_ADMIN_AID`]
/// is selected.
pub const NITROKEY_GET_ADMIN_STATUS: [u8; 4] = [0x00, 0x80, 0x00, 0x00];

/// Trussed/Nitrokey admin application management command (`INS 0x62`), a
/// bare case-1 APDU (no data, no `Le`) answering with the device's serial
/// number as an unsigned big-endian 128-bit integer — decoded by
/// [`crate::parse_serial`] like any other serial reply. Only meaningful once
/// [`NITROKEY_ADMIN_AID`] is selected.
pub const NITROKEY_GET_SERIAL: [u8; 4] = [0x00, 0x62, 0x00, 0x00];

/// Trussed/Nitrokey admin application management command: `GET_VERSION`
/// (`INS 0x61`) with `P1 = 0x01` for its string-output form (rather than the
/// binary form other `P1` values select), answering with the firmware
/// version as plain ASCII (e.g. `"1.2.3"`), decoded by [`parse_ascii_text`]
/// and [`parse_dotted_version`]. Only meaningful once [`NITROKEY_ADMIN_AID`]
/// is selected.
pub const NITROKEY_GET_VERSION_STRING: [u8; 5] = [0x00, 0x61, 0x01, 0x00, 0x00];

/// Swissbit's officially registered RID (Registered Application Provider
/// Identifier) — `D2 76 00 01 62`, published in the German card-issuer RID
/// registry at
/// <https://www.kartenbezogene-identifier.de/de/rapi/rid-liste.html>. A
/// token whose select identity fingerprints as `OpenFips201` qualifies for
/// [`OpenFips201Variant::SwissbitIShield2`] when SELECTing this RID succeeds
/// with `SW = 9000` — the transport layer SELECTs it (then re-SELECTs PIV)
/// and passes the result to [`classify`] as `swissbit_rid_selectable`.
pub const SWISSBIT_RID: [u8; 5] = [0xD2, 0x76, 0x00, 0x01, 0x62];

/// HID Crescendo C2300's GET PIV PROPERTIES data object tag — read like any
/// other PIV data object, via [`crate::get_data`] (which frames it as `5C 03
/// FF FF 7F`), per HID's own C2300 low-level API reference:
/// <https://docs.hidglobal.com/crescendo/api/low-level/get-piv-properties.htm>
/// (the APDU itself, and the response's top-level tag list, are all that
/// page documents — see [`parse_hid_crescendo_slot_key_algorithms`]'s doc for why the
/// C4000 API reference,
/// <https://docs.hidglobal.com/crescendo/api/c4000/get-piv-properties.htm>,
/// ends up being this crate's real source for what's *inside* each tag).
/// The response repeats a `0x51` "PKI Object Properties" TLV once per PKI
/// slot the card supports; [`parse_hid_crescendo_slot_key_algorithms`] decodes the
/// fields this crate needs out of each.
///
/// The C4000 family exposes the same GET PIV PROPERTIES data — the two
/// families' responses overlap on the handful of fields this crate actually
/// reads, though not on their overall shape; see
/// [`parse_hid_crescendo_slot_key_algorithms`]'s doc for the specific differences a
/// live C2300 trace turned up against the C4000 reference — framed as a
/// different, proprietary command instead of a standard GET DATA read — see
/// [`HID_CRESCENDO_C4000_GET_PROPERTIES`] — so this tag/request shape is
/// only meaningful once [`classify`] has already narrowed the device to
/// C2300 specifically.
pub const HID_CRESCENDO_C2300_PROPERTIES_TAG: [u8; 3] = [0xFF, 0xFF, 0x7F];

/// HID Crescendo C4000's GET PIV PROPERTIES request — unlike C2300's (a
/// standard GET DATA read for [`HID_CRESCENDO_C2300_PROPERTIES_TAG`]), this
/// is C4000's own proprietary case-2 command: `CLA 80h INS 56h P1 00h P2
/// 00h`, `Le` `00h` (meaning "up to 256 bytes", extended by the usual
/// `61xx`/GET RESPONSE chain for a longer reply) — per HID's C4000 API
/// reference: <https://docs.hidglobal.com/crescendo/api/c4000/get-piv-properties.htm>.
/// The response is decoded by the same [`parse_hid_crescendo_slot_key_algorithms`]/
/// [`parse_hid_crescendo_version`] C2300 uses — see those functions' docs
/// for how this same C4000 reference also ends up documenting the fields
/// this crate reads out of the C2300 family's own response body, which
/// HID's dedicated C2300 reference
/// (<https://docs.hidglobal.com/crescendo/api/low-level/get-piv-properties.htm>)
/// leaves undocumented — and for the response's *overall* shape, which
/// turns out not to match between the two families nearly as closely as
/// that one shared detail might suggest.
pub const HID_CRESCENDO_C4000_GET_PROPERTIES: [u8; 5] = [0x80, 0x56, 0x00, 0x00, 0x00];

/// GlobalPlatform's Issuer Security Domain (the card's built-in "Card
/// Manager") RID+PIX — `A0 00 00 01 51 00 00`. Unlike every other AID/RID in
/// this module, this one is a GlobalPlatform Card Specification standard,
/// not vendor-specific — present on essentially every GlobalPlatform-
/// compliant card, HID Crescendo units included. Selecting it is the
/// precondition for [`GLOBAL_PLATFORM_GET_CPLC`]: CPLC data is only readable
/// while the Issuer Security Domain itself, not PIV or any other applet, is
/// the currently-selected application.
///
/// `keyroost_transport::PivSession` selects this — and reads CPLC — before
/// PIV is ever selected, not as one of the mid-session fingerprinting probes
/// this module's other AIDs are (see [`FEITIAN_RID`] and friends, each
/// followed by an unconditional re-SELECT of PIV): once PIV management-key
/// authentication has happened, selecting a second applet drops it the same
/// way switching to any other applet does, and there is no re-SELECT that
/// restores it afterward — so this probe has to run first or not at all. See
/// `PivSession::probe_hid_crescendo_cplc_serial`'s doc for the full story.
pub const GLOBAL_PLATFORM_ISD_AID: [u8; 7] = [0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00];

/// GlobalPlatform `GET DATA` for Card Production Life Cycle (CPLC) data:
/// `CLA 80h INS CAh P1 9Fh P2 7Fh Le 00h`, a case-2 APDU with no command
/// data. Standard GlobalPlatform Card Specification command (data object tag
/// `9F 7F`), not HID-specific — only meaningful once
/// [`GLOBAL_PLATFORM_ISD_AID`] is selected. [`parse_cplc_serial`] decodes the
/// one field keyroost reads out of the reply.
pub const GLOBAL_PLATFORM_GET_CPLC: [u8; 5] = [0x80, 0xCA, 0x9F, 0x7F, 0x00];

/// Decode a HID Crescendo unit's on-card printed serial number out of a
/// GlobalPlatform CPLC ([`GLOBAL_PLATFORM_GET_CPLC`]) reply.
///
/// The Card Production Life Cycle structure GlobalPlatform standardizes is a
/// fixed 42-byte layout — IC Fabricator (2 bytes), IC Type (2), Operating
/// System ID (2), OS release date (2), OS release level (2), IC fabrication
/// date (2), IC Serial Number (4), IC Batch Identifier (2), then ten further
/// fields this crate has no use for — optionally wrapped in the tag itself
/// (`9F 7F <len>`) the way a GET DATA reply for any other object is. Both
/// forms are accepted here, the same tolerant-unwrap discipline
/// [`parse_hid_crescendo_slot_key_algorithms`]/[`parse_hid_crescendo_version`]
/// already use for their own GET PIV PROPERTIES replies: a reply starting
/// with tag `9F 7F` is unwrapped first, anything else is assumed to already
/// be the bare CPLC value.
///
/// HID's own on-card printed serial (confirmed against a live unit) is four
/// of those eighteen fields, concatenated in a different order than they
/// appear in the raw structure — IC Fabricator, then IC Type, then IC Batch
/// Identifier, then IC Serial Number — with every nibble of the resulting 10
/// bytes read as one decimal digit (IC Fabricator/Type/Batch each print as 4
/// digits, IC Serial Number as 8, 20 digits total, confirmed against the
/// same live unit): the same "nibble is a decimal digit" convention
/// `keyroost_transport::decode_bcd_serial` implements for Token2's BCD GET
/// SERIAL quirk, reimplemented here rather than shared since this crate
/// doesn't depend on `keyroost-transport`.
///
/// `None` when the reply (after unwrapping) is shorter than 18 bytes — not
/// enough to reach IC Batch Identifier, the last of the four fields this
/// needs, which starts at offset 16 — or when any nibble of the ten
/// concatenated bytes falls outside `0..=9`, the same "fail safe rather than
/// report a wrong number" discipline `decode_bcd_serial` uses.
#[must_use]
pub fn parse_cplc_serial(data: &[u8]) -> Option<u128> {
    let cplc = if data.first() == Some(&0x9F) && data.get(1) == Some(&0x7F) {
        let (len, header) = crate::read_ber_len(data.get(2..)?).ok()?;
        data.get(2 + header..(2 + header).checked_add(len)?)?
    } else {
        data
    };
    if cplc.len() < 18 {
        return None;
    }
    let ic_fabricator = &cplc[0..2];
    let ic_type = &cplc[2..4];
    let ic_serial_number = &cplc[12..16];
    let ic_batch_identifier = &cplc[16..18];
    let mut decoded: u128 = 0;
    for byte in ic_fabricator
        .iter()
        .chain(ic_type)
        .chain(ic_batch_identifier)
        .chain(ic_serial_number)
    {
        for nibble in [byte >> 4, byte & 0xF] {
            if nibble > 9 {
                return None;
            }
            decoded = decoded * 10 + u128::from(nibble);
        }
    }
    Some(decoded)
}

/// The ACA (Access Control Applet) instance AID, `A0 00 00 00 79 10 00` —
/// NIST GSC-IS 2.1's Access Control Applet, partially standardized there but
/// carrying vendor-specific extensions on top. Most HID Crescendo units
/// (C2300 and C4000 alike; confirmed on a live C2300 unit that answers
/// `SW = 6D 00` "instruction not supported" to a standard PIV `GENERAL
/// AUTHENTICATE` on key reference `0x9B` — it simply doesn't model a PIV
/// management key as a real object at all, per
/// [`hid_crescendo_reports_slot`]) instead gate PIV admin operations behind
/// this applet's `EXTERNAL AUTHENTICATE` with "XAUTH key 1" — see
/// [`HID_CRESCENDO_ACA_GET_CHALLENGE`]/[`hid_crescendo_aca_external_authenticate`],
/// documented separately for each family:
/// <https://docs.hidglobal.com/crescendo/api/low-level/external-auth-xauth.htm>
/// (scoped by that page's own note to "devices belonging to the Crescendo
/// 2300 family") and
/// <https://docs.hidglobal.com/crescendo/api/c4000/external-auth-xauth.htm>.
/// The two disagree on `GET CHALLENGE`'s `P2` — see
/// [`HID_CRESCENDO_ACA_GET_CHALLENGE`]'s own doc for how that's reconciled —
/// but a C4000 unit is otherwise already assumed (undocumented, unconfirmed
/// on hardware) to share C2300's non-support of the standard management
/// key — see
/// `keyroost_piv::compat`'s `GET_METADATA_VERDICTS`'s C4000 bullet for the
/// same caveat applied there — so `keyroost_transport::PivSession` tries this
/// same sequence for either variant, and indeed for
/// [`HidCrescendoVariant::Generic`] too, rather than only the one family
/// the page names.
///
/// Selected the same way [`SWISSBIT_RID`]/[`FEITIAN_RID`]/
/// [`NITROKEY_ADMIN_AID`] are (`crate::select_by_aid`), but for a different
/// reason: those probes SELECT, read one bit of information, and
/// unconditionally re-SELECT PIV, discarding whatever state the temporary
/// SELECT left behind. This one is not discarded — the ACA's "External
/// Authentication" access condition, once satisfied, is a *card-wide* grant
/// under NIST GSC-IS 2.1's access-condition model, not scoped to the ACA
/// instance itself, so it is still in effect after switching back to PIV.
/// That's the entire reason this mechanism can substitute for PIV's own
/// `0x9B` `GENERAL AUTHENTICATE`: re-selecting PIV afterward is how the
/// access condition actually reaches the PIV applet's admin commands, not a
/// step that throws the authentication away. (Re-selecting PIV *does* still
/// throw away a prior standard `0x9B` authentication, same as always — the
/// two mechanisms just differ on whether a PIV re-select is itself
/// authentication-preserving or authentication-clearing.)
pub const HID_CRESCENDO_ACA_AID: [u8; 7] = [0xA0, 0x00, 0x00, 0x00, 0x79, 0x10, 0x00];

/// ACA `GET CHALLENGE` (`CLA 00h INS 84h P1 00h P2 01h Le 00h`, a case-2
/// APDU with no command data): the first step of the External Authentication
/// sequence, requesting a fresh card challenge for XAUTH key 1. Only
/// meaningful once [`HID_CRESCENDO_ACA_AID`] is selected.
///
/// The two documented families disagree on `P2` here: C2300's page
/// (<https://docs.hidglobal.com/crescendo/api/low-level/external-auth-xauth.htm>)
/// gives `P2 00h`, while C4000's own page
/// (<https://docs.hidglobal.com/crescendo/api/c4000/external-auth-xauth.htm>)
/// gives `P2 01h` for the identical command. Confirmed by experiment against
/// live C2300 hardware that `P2 01h` — C4000's value — works there too, so
/// this crate sends `01h` unconditionally rather than branching on variant;
/// one wire form for both rather than two untested-in-the-other-direction
/// ones. (`EXTERNAL AUTHENTICATE`'s own `P2` — see
/// [`hid_crescendo_aca_external_authenticate`] — is `01h` on both pages
/// already and needed no such reconciliation.)
///
/// Per either page, the response's own length is the only place the XAUTH
/// key's algorithm is named — see [`hid_crescendo_xauth_key_alg`].
pub const HID_CRESCENDO_ACA_GET_CHALLENGE: [u8; 5] = [0x00, 0x84, 0x00, 0x01, 0x00];

/// The P2 reference the ACA instance's own VERIFY PIN answers, per
/// <https://docs.hidglobal.com/crescendo/api/low-level/verify-pin.htm>:
/// `CLA 00h INS 20h P1 00h P2 00h`. Note the `0x00` — **not**
/// [`crate::PIN_REF_APPLICATION`] (`0x80`), the reference the standard PIV
/// VERIFY (and every other fingerprint's [`PivExtension::PinManagementAuth`])
/// uses. A VERIFY sent with the standard PIV reference while ACA is the
/// currently-selected applet is not this command — pass this reference to
/// [`crate::verify_pin_at`] instead whenever ACA is selected, e.g.
/// immediately before PUT XAUTH KEY
/// (`keyroost_transport::PivSession::hid_crescendo_aca_put_xauth_key_op`'s
/// PIN-unlock branch).
///
/// [`PivExtension::PinManagementAuth`]: crate::compat::PivExtension::PinManagementAuth
pub const HID_CRESCENDO_ACA_PIN_REF: u8 = 0x00;

/// The XAUTH key 1 algorithm implied by a [`HID_CRESCENDO_ACA_GET_CHALLENGE`]
/// response's length. Per HID's own documentation: "The length of the Get
/// Challenge response indicates the key type of XAUTH key 1: 8 bytes for a
/// TDES Administration key, 16 bytes for an AES-128 Administration key" —
/// conveniently, both lengths already correspond to one of this crate's own
/// [`crate::MgmtAlg`] variants ([`crate::MgmtAlg::TripleDes`]'s and
/// [`crate::MgmtAlg::Aes128`]'s `key_len()`s respectively), so no separate
/// key-type enum is needed here. `None` for any other length — HID's
/// documentation names no third option.
#[must_use]
pub fn hid_crescendo_xauth_key_alg(challenge_len: usize) -> Option<crate::MgmtAlg> {
    match challenge_len {
        8 => Some(crate::MgmtAlg::TripleDes),
        16 => Some(crate::MgmtAlg::Aes128),
        _ => None,
    }
}

/// ACA `EXTERNAL AUTHENTICATE` with XAUTH key 1 (`CLA 00h INS 82h P1 00h P2
/// 01h`, `Lc` = `host_cryptogram.len()`, no `Le` — HID's own documentation:
/// "The response message is always empty", so success or failure is carried
/// purely by the status word): the second and final step of the sequence
/// [`HID_CRESCENDO_ACA_GET_CHALLENGE`] starts. `host_cryptogram` is that
/// step's card challenge, single-block ECB-encrypted under XAUTH key 1 —
/// `keyroost_transport::PivSession` computes that with the very same
/// block-cipher primitive it already uses for standard PIV management-key
/// auth, keyed by the [`crate::MgmtAlg`] [`hid_crescendo_xauth_key_alg`]
/// names. `Lc` is read off `host_cryptogram.len()` rather than taken as a
/// separate algorithm argument here, so the two can never disagree.
///
/// Per HID's documentation, three failure status words are distinguished
/// (beyond the generic "wrong key" case, `SW = 63 00`): `SW = 6A 88` ("XAUTH
/// 1 key has not been initialized"), `SW = 69 85` ("The Get Challenge
/// command has not been sent before the command"). Neither gets special
/// handling here — both still mean "authentication did not succeed", which
/// is all a caller needs to know — but a `--debug` trace still shows the raw
/// status word for whoever's diagnosing a real device against this.
#[must_use]
pub fn hid_crescendo_aca_external_authenticate(host_cryptogram: &[u8]) -> Vec<u8> {
    let mut apdu = Vec::with_capacity(5 + host_cryptogram.len());
    apdu.extend_from_slice(&[0x00, 0x82, 0x00, 0x01, host_cryptogram.len() as u8]);
    apdu.extend_from_slice(host_cryptogram);
    apdu
}

/// ACA `PUT XAUTH KEY` (`CLA 00h INS D8h P1 01h` — "XAUTH key 1", the same
/// key [`hid_crescendo_aca_external_authenticate`] authenticates against —
/// `P2 00h`), installing a new XAUTH key value: HID's own replacement for
/// the standard PIV SET MANAGEMENT KEY extension on a device that doesn't
/// implement it (see [`HID_CRESCENDO_ACA_AID`]'s doc). Case 3 — no `Le`, and
/// per HID's documentation the response data field is always empty on
/// success, so success or failure is carried purely by the status word,
/// same as [`hid_crescendo_aca_external_authenticate`].
///
/// `alg` must be [`crate::MgmtAlg::TripleDes`] or [`crate::MgmtAlg::Aes128`]
/// — the only two algorithms HID's documentation names for XAUTH key 1
/// (mirroring [`hid_crescendo_xauth_key_alg`]'s decode direction) — and
/// `key` must be exactly `alg.key_len()` bytes; `None` on either mismatch,
/// so a caller can surface the same "bad key length" error the standard PIV
/// path already uses instead of building a malformed command.
///
/// Data field, per
/// <https://docs.hidglobal.com/crescendo/api/low-level/put-xauth-key.htm>:
///
/// | offset | len | value | meaning |
/// |---|---|---|---|
/// | 0 | 1 | `0x00` | RFU |
/// | 1 | 1 | `alg.id()` (`0x03`/`0x08` — TDES ECB / 128-AES ECB; conveniently the same byte [`crate::MgmtAlg::id`] already returns for standard PIV) | Algorithm |
/// | 2 | 1 | `key.len() + 1` (`0x19`/`0x11`) | Key data length indicator |
/// | 3 | 1 | `key.len()` (`0x18`/`0x10`) | Real key length |
/// | 4 | `key.len()` | `key` | Key value |
/// | 4+n | 1 | `0x00` | Key check value length |
///
/// `Lc` (`0x1D` for TDES, `0x15` for AES-128 — matching HID's documented
/// values) falls straight out of that layout's total length, so it needs no
/// separate table here.
///
/// Requires "PIN or XAUTH1" access per HID's documentation, same
/// precondition [`hid_crescendo_aca_external_authenticate`] runs under — the
/// ACA instance must already be selected and either a PIN VERIFY or a prior
/// [`hid_crescendo_aca_external_authenticate`] round must have already
/// succeeded.
#[must_use]
pub fn hid_crescendo_aca_put_xauth_key(alg: crate::MgmtAlg, key: &[u8]) -> Option<Vec<u8>> {
    if !matches!(alg, crate::MgmtAlg::TripleDes | crate::MgmtAlg::Aes128) {
        return None;
    }
    if key.len() != alg.key_len() {
        return None;
    }
    let mut data = Vec::with_capacity(4 + key.len() + 1);
    data.push(0x00); // RFU
    data.push(alg.id());
    data.push((key.len() + 1) as u8); // key data length indicator
    data.push(key.len() as u8); // real key length
    data.extend_from_slice(key);
    data.push(0x00); // key check value length
    let mut apdu = Vec::with_capacity(5 + data.len());
    apdu.extend_from_slice(&[0x00, 0xD8, 0x01, 0x00, data.len() as u8]);
    apdu.extend_from_slice(&data);
    Some(apdu)
}

/// [`hid_crescendo_aca_put_xauth_key`]'s "remove" form: PUT XAUTH KEY with
/// the documented `Lc = 0x04` short data field that deletes XAUTH key 1
/// outright instead of installing a new one — HID's own equivalent of a PIV
/// device having no management key at all, offered as a distinct "Delete"
/// choice (rather than always requiring a replacement key) precisely
/// because a HID Crescendo unit's management key isn't a real PIV object
/// with a mandatory-key invariant to preserve.
///
/// Per <https://docs.hidglobal.com/crescendo/api/low-level/put-xauth-key.htm>'s
/// data-field table, the Algorithm byte is never optional — every row of
/// that table pairs it with a real key-data-length value, so a removal
/// still names one, unconditionally `0x03` (TDES ECB): a "0 bytes to
/// remove the corresponding key, in this case the following bytes are
/// absent" length indicator makes the algorithm choice moot in practice
/// (there's no key value left to interpret under it either way), and TDES
/// is the algorithm this crate's own install form ([`hid_crescendo_aca_put_xauth_key`])
/// already defaults to when a card's actual key algorithm isn't otherwise
/// known — this removes XAUTH key 1 regardless of whether it currently
/// holds a TDES or an AES-128 key:
///
/// | offset | len | value | meaning |
/// |---|---|---|---|
/// | 0 | 1 | `0x00` | RFU |
/// | 1 | 1 | `0x03` | Algorithm (TDES ECB), sent unconditionally |
/// | 2 | 1 | `0x00` | Key data length indicator (`0x00` = remove) |
/// | 3 | 1 | `0x00` | Real key length |
///
/// Whether XAUTH key 1 being absent afterward disables the ACA's "PIN or
/// XAUTH1" access condition down to PIN-only, or removes key-based unlock
/// entirely, is undocumented and unconfirmed on hardware — same caveat as
/// every other assumption in this module without a live-device trace to
/// check it against.
#[must_use]
pub fn hid_crescendo_aca_put_xauth_key_remove() -> Vec<u8> {
    vec![0x00, 0xD8, 0x01, 0x00, 0x04, 0x00, 0x03, 0x00, 0x00]
}

/// ACA `RESET CARD` (`CLA 00h INS 38h P1 00h P2 00h`, case 1 — no `Lc`, no
/// data, no `Le`): HID's device-wide reset, backing
/// [`crate::compat::PivExtension::ResetGlobal`]. Confirmed identical on both
/// documented families —
/// <https://docs.hidglobal.com/crescendo/api/low-level/reset-card.htm>
/// (scoped by that page's own note to "devices belonging to the Crescendo
/// 2300 family") and
/// <https://docs.hidglobal.com/crescendo/api/c4000/reset-card.htm> — same
/// APDU, same "PIN or XAUTH1" access condition
/// [`hid_crescendo_aca_external_authenticate`]/[`HID_CRESCENDO_ACA_PIN_REF`]
/// already satisfy, same `SW = 69 82` ("access condition not satisfied") /
/// `SW = 90 00` pair.
///
/// What it clears, per those two pages (the C4000 page states each item
/// unconditionally; the C2300 page's OATH line reads "(HID Crescendo Key
/// only)", and only the C4000 page claims FIDO at all — see
/// [`crate::compat::PivExtension::ResetGlobal`]'s doc for how a caller
/// should read that split): XAUTH key 1 itself, the PIV PIN (reset to a
/// documented default — `000000` per the C4000 page, `00000000` per the
/// C2300 page), every PKI key and PIV data container, OATH keys/config, and
/// (C4000 only, as documented) FIDO credentials. The device is left in
/// HID's own "manufacturing state" language.
///
/// Only meaningful once [`HID_CRESCENDO_ACA_AID`] is selected and
/// authenticated — same precondition, same discipline as every other ACA
/// command in this module.
pub const HID_CRESCENDO_ACA_RESET_CARD: [u8; 4] = [0x00, 0x38, 0x00, 0x00];

/// HID's documented factory-delivery value for XAUTH key 1: 24 zero bytes,
/// 3DES ([`crate::MgmtAlg::TripleDes`]). [`HID_CRESCENDO_ACA_RESET_CARD`]
/// clears XAUTH key 1 outright rather than restoring it to this value on
/// its own, but every unit ships with it already set to this all-zero key —
/// a caller that wants the device back at its as-delivered state, not
/// merely "wiped", has to `PUT XAUTH KEY`
/// ([`hid_crescendo_aca_put_xauth_key`]) with this value explicitly right
/// after. It matters practically too, not just cosmetically: XAUTH1 is the
/// *other* half of RESET CARD's own "PIN or XAUTH1" access condition, so
/// restoring a known key is what keeps the device recoverable by XAUTH
/// alone if a later mistake ever blocks the ACA's own PIN.
pub const HID_CRESCENDO_ACA_FACTORY_XAUTH_KEY: [u8; 24] = [0u8; 24];

/// The ACA's own PIN immediately after [`HID_CRESCENDO_ACA_RESET_CARD`] —
/// confirmed on hardware to be `00000000` (eight ASCII `'0'`s), the C2300
/// page's documented value. [`HID_CRESCENDO_ACA_RESET_CARD`]'s own security
/// status does not survive RESET CARD (also confirmed on hardware, resolving
/// the "unverified" caveat this constant's callers used to carry), so a
/// caller that wants to run any further ACA command in the same session —
/// [`hid_crescendo_aca_put_xauth_key`] to restore
/// [`HID_CRESCENDO_ACA_FACTORY_XAUTH_KEY`], most notably — has to
/// re-authenticate against this PIN first, not against whatever credential
/// unlocked the session before RESET CARD ran.
pub const HID_CRESCENDO_ACA_PIN_AFTER_RESET: &[u8] = b"00000000";

/// Decode every `(key_ref, algorithm_id)` pair for a slot that actually
/// holds a key out of a HID Crescendo GET PIV PROPERTIES response (C2300's
/// [`HID_CRESCENDO_C2300_PROPERTIES_TAG`] or C4000's
/// [`HID_CRESCENDO_C4000_GET_PROPERTIES`] — both families answer with the
/// same TLV structure this decodes) — one pair per `0x51` "PKI Object
/// Properties" block the response repeats (one per PKI slot the card
/// supports), so a caller reads every slot's algorithm off a single round
/// trip rather than needing one per slot.
///
/// Two HID API references cover this response, unevenly: the C2300 one
/// (<https://docs.hidglobal.com/crescendo/api/low-level/get-piv-properties.htm>)
/// documents the APDU and the response's top-level tag list, but says
/// nothing about what's inside a `0x51`/`0x50` block or a `0x43` subtag —
/// every byte offset this function relies on instead comes from the C4000
/// one
/// (<https://docs.hidglobal.com/crescendo/api/c4000/get-piv-properties.htm>),
/// which fills that gap in quite well *for the fields this function reads*.
/// It is not, though, a faithful map of the *whole* response on either
/// family — a live C2300 trace this crate was built and tested against
/// diverges from the C4000 reference in more places than just subtag
/// `0x43`'s length (the difference usually worth calling out):
///
/// * top level: the C2300 trace carries tags `0x3B` and `0x45`, neither of
///   which appears anywhere in the C4000 reference's tag table; conversely
///   the C4000 reference documents a `0x40` tag (container/PKI object
///   counts) the C2300 trace never sends.
/// * inside a `0x50` block ("Generic Container Object Properties"): the
///   C2300 trace's subtags are `0x47`/`0x26`/`0x42`; the C4000 reference
///   documents `0x47`/`0x42`/`0x4D` for the same block — `0x26` isn't in
///   the C4000 table at all, and the C4000-documented `0x4D` (Access
///   Control Rules) never appears in the C2300 trace.
/// * inside a `0x51` block: the C2300 trace's subtags are `0x47`/`0x26`/
///   `0x48`/`0x43`/`0x42`; the C4000 reference documents only `0x48`/
///   `0x43`/`0x4D` for the same block.
/// * subtag `0x43` itself: 4 bytes on the C2300 trace, 5 (an appended "Key
///   Purpose" byte) per the C4000 reference — the one difference already
///   well-known enough to get its own mention below.
///
/// None of that matters here, which is exactly why this function is
/// written the way it is: [`crate::find_tlv`] looks up subtags `0x48`/
/// `0x43` inside a `0x51` block by tag number alone, regardless of what
/// other subtags surround them, in what order, or whether they're present
/// at all — and the top-level walk below does the same for tag `0x51`
/// itself among whatever else the response carries. The C4000 reference
/// stays the right source for what's *inside* `0x43` specifically
/// (algorithm ID, key length, the two initialization-status bytes below) —
/// that much is confirmed compatible against real C2300 hardware — it just
/// isn't a description of the response's shape as a whole on either
/// family, so nothing here assumes it is.
///
/// The reply is a standard PIV GET DATA response shape: everything wrapped
/// in one outer `0x53` "Discretionary Data Object" TLV, unwrapped the same
/// way [`crate::unwrap_data_object`] does for any other PIV data object —
/// tolerantly: the C4000 reference describes the response's top-level tags
/// directly, without mentioning a `0x53` wrapper the way the C2300
/// reference explicitly does, so a reply that doesn't start with `0x53` is
/// treated as already-unwrapped discretionary data rather than rejected
/// outright. Inside it, tag `0x51` repeats once per slot — unlike
/// [`crate::find_tlv`], which only ever returns the *first* match for a
/// tag, this walks the discretionary data's top level by hand to visit
/// every `0x51` occurrence. Within each `0x51` block, subtag `0x48` ("Key
/// Reference", 1 byte) names the slot this block describes, and subtag
/// `0x43` ("Cryptographic parameters") carries, per the C4000 reference:
/// byte 0 the algorithm identifier, byte 1 the key length, and bytes 2/3
/// the private/public key *initialization status* (`0x00` = not
/// initialized, `0x01` = generated, `0x81` = injected) — a slot's `0x51`
/// block exists once its PKI container is allocated, which can be before a
/// key is ever generated into it, so the algorithm byte alone doesn't say
/// whether a key is actually present. A block whose private *and* public
/// status are both `0x00` is skipped entirely — a container with no key
/// loaded is exactly the same as no `0x51` block at all, to any caller —
/// confirmed against a real (unprovisioned) C2300 unit whose five `0x51`
/// blocks all read this way despite naming a plausible-looking algorithm
/// byte. The C2300 family's `0x43` is one byte shorter than the C4000
/// family's — the appended "Key Purpose" byte mentioned above — which
/// doesn't affect any of the four bytes this reads, since both live well
/// within the shorter length. (The Crescendo SDK's `PKIObject` class
/// corroborates that one shared detail — `AlgorithmID` "Extracted from tag
/// 0x43" and separate `PrivateKeyInitialized`/`PublicKeyInitialized`
/// booleans:
/// <https://docs.hidglobal.com/hid-crescendo-sdk-v1.2/API%20references/html/classCrescendoDLL_1_1PCSC_1_1PKIObject.html>.)
///
/// A `0x51` block missing subtag `0x48` or `0x43` entirely (as opposed to
/// one that has `0x43` but reports no key loaded) is likewise skipped
/// rather than aborting the whole parse — the same "keep whatever parsed
/// cleanly" spirit as `compact_tlv`. Never `None` — an unparseable
/// response, or one with no usable `0x51` block, is an empty `Vec`, same as
/// a well-formed response simply naming no occupied slot.
#[must_use]
pub fn parse_hid_crescendo_slot_key_algorithms(data: &[u8]) -> Vec<(u8, u8)> {
    let discretionary = crate::unwrap_data_object(data).unwrap_or(data);
    hid_crescendo_slot_blocks(discretionary)
        .into_iter()
        .filter_map(|value| {
            let key_ref = crate::find_tlv(value, 0x48).and_then(|v| v.first().copied())?;
            let params = crate::find_tlv(value, 0x43)?;
            let alg_id = params.first().copied()?;
            // Bytes 2/3: private/public key initialization status. `0x00`
            // on both means the slot's container exists but no key was
            // ever generated or injected into it — see this function's doc.
            let key_loaded =
                params.get(2).is_some_and(|&b| b != 0) || params.get(3).is_some_and(|&b| b != 0);
            key_loaded.then_some((key_ref, alg_id))
        })
        .collect()
}

/// Walk the (already tolerantly unwrapped) discretionary data of a HID
/// Crescendo GET PIV PROPERTIES response and collect every top-level tag
/// `0x51` "PKI Object Properties" block's raw value, in order. Shared by
/// [`parse_hid_crescendo_slot_key_algorithms`] (which further filters by
/// initialization status) and [`hid_crescendo_reports_slot`] (which only
/// cares whether a slot's block exists at all, regardless of that status) —
/// see the former's doc for the walk itself and the "keep whatever parsed
/// cleanly" behavior on a malformed length.
fn hid_crescendo_slot_blocks(discretionary: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < discretionary.len() {
        let tag = discretionary[i];
        let Some(len_buf) = discretionary.get(i + 1..) else {
            break;
        };
        let Ok((len, header)) = crate::read_ber_len(len_buf) else {
            break;
        };
        let vstart = i + 1 + header;
        let Some(vend) = vstart.checked_add(len) else {
            break;
        };
        let Some(value) = discretionary.get(vstart..vend) else {
            break;
        };
        if tag == 0x51 {
            out.push(value);
        }
        i = vend;
    }
    out
}

/// Whether a HID Crescendo GET PIV PROPERTIES response names `key_ref` in
/// any top-level `0x51` block at all — regardless of that slot's
/// initialization status (unlike
/// [`parse_hid_crescendo_slot_key_algorithms`], which only returns slots
/// with a key actually loaded, and would therefore give a false "no" for a
/// management key block that exists but reports as uninitialized).
///
/// The one caller this exists for is
/// `keyroost_transport::PivSession::authenticate_management`, checking
/// `key_ref = `[`crate::KEY_REF_MANAGEMENT`]` (`0x9B`): most HID Crescendo
/// units don't model the PIV management key as a real object through GET PIV
/// PROPERTIES at all (a live C2300 unit answers `SW = 6D 00` to a standard
/// PIV `GENERAL AUTHENTICATE` on `0x9B` outright), in which case
/// `authenticate_management` falls back to the vendor ACA XAUTH admin-auth
/// mechanism instead — see [`HID_CRESCENDO_ACA_AID`]'s doc. A minority are
/// documented to expose it properly (HID's own Crescendo Manager
/// documentation: <https://docs.hidglobal.com/crescendo-manager/CM/about-cm.htm>),
/// in which case the standard mechanism is used unchanged, same as any other
/// PIV applet.
#[must_use]
pub fn hid_crescendo_reports_slot(data: &[u8], key_ref: u8) -> bool {
    let discretionary = crate::unwrap_data_object(data).unwrap_or(data);
    hid_crescendo_slot_blocks(discretionary)
        .into_iter()
        .any(|value| crate::find_tlv(value, 0x48) == Some(&[key_ref]))
}

/// Decode a HID Crescendo GET PIV PROPERTIES response's own applet version
/// (C2300 or C4000 alike — see [`parse_hid_crescendo_slot_key_algorithms`] for why
/// the two families' responses are handled together, and for why the C4000
/// API reference
/// (<https://docs.hidglobal.com/crescendo/api/c4000/get-piv-properties.htm>)
/// is this crate's source for tag `0x01`'s byte layout even on a C2300
/// device, whose own reference
/// (<https://docs.hidglobal.com/crescendo/api/low-level/get-piv-properties.htm>)
/// names the tag but never describes its contents) — top-level tag `0x01`,
/// "Applet Version Block", read out of the same (tolerantly) unwrapped
/// discretionary data [`parse_hid_crescendo_slot_key_algorithms`] reads tag `0x51`
/// from ([`crate::find_tlv`] is enough here since `0x01` isn't repeated the
/// way `0x51`/`0x50` are).
///
/// This is the only version source keyroost has for HID Crescendo: the
/// whole product line doesn't answer Yubico's own GET VERSION extension
/// (`INS 0xFD`) at all. It's still an *applet* version, though — HID's own
/// documentation names the tag "Applet Version Block" — so
/// `keyroost-transport`'s `PivSession` feeds it in as a stand-in for that
/// missing Yubico reply, and [`crate::compat::resolve`]/
/// [`crate::compat::resolve_quirks`] compare it on the applet version axis,
/// not the separate firmware one.
///
/// Per the C4000 reference, the tag's value is 6 bytes: a family identifier
/// (`0x21`) followed by a fixed 5-byte version (`04 00 00 XX YY`). The live
/// C2300 unit this was confirmed against instead reports a 5-byte value,
/// `21 03 00 03 06` — family `0x21` again, but only 4 version bytes — one
/// more instance of the length mismatches [`parse_hid_crescendo_slot_key_algorithms`]'s
/// doc catalogs between what the C4000 reference describes and what a real
/// C2300 device actually sends. Rather than assume either family's exact
/// length, this only ever treats the first byte as the family (to strip)
/// and everything after it as "however many version-segment bytes happen to
/// be there." This strips the leading family byte and returns just the
/// version segment bytes (`[3, 0, 3, 6]` for that C2300 unit) — the family
/// byte isn't itself a version component, and comparing it as one would
/// misorder any two units that happen to share a version but not a family.
///
/// `None` when tag `0x01` is absent or its value is empty (no family byte
/// to strip even) — never because the response failed to unwrap, since this
/// tolerates a missing `0x53` wrapper the same way
/// [`parse_hid_crescendo_slot_key_algorithms`] does.
#[must_use]
pub fn parse_hid_crescendo_version(data: &[u8]) -> Option<Vec<u8>> {
    let discretionary = crate::unwrap_data_object(data).unwrap_or(data);
    let (_family, version) = crate::find_tlv(discretionary, 0x01)?.split_first()?;
    Some(version.to_vec())
}

/// Resolve a HID Crescendo GET PIV PROPERTIES algorithm-identifier byte
/// (from [`parse_hid_crescendo_slot_key_algorithms`]) to a [`crate::KeyAlg`].
///
/// Deliberately not the same table as [`crate::KeyAlg::from_id`] (Yubico's
/// GET METADATA encoding): both agree on RSA-2048/3072 and ECC P-256/P-384,
/// but HID's own C4000 API reference documents RSA-4096 as `0x04` where
/// Yubico's scheme uses `0x16` —
/// <https://docs.hidglobal.com/crescendo/api/c4000/get-piv-properties.htm> —
/// so this can't just defer to `from_id`. Once again the C4000 reference is
/// doing double duty here: HID's C2300 reference
/// (<https://docs.hidglobal.com/crescendo/api/low-level/get-piv-properties.htm>)
/// never lists algorithm-identifier values at all, so no C2300 hardware
/// wide enough to cover every algorithm has been available to directly
/// confirm the C2300 family uses this exact same byte table; it's assumed
/// to, since both families share the same
/// `PIVCryptographicMechanismIdentifier`-typed field in HID's own Crescendo
/// SDK, and it's the only documented mapping keyroost has for either.
#[must_use]
pub fn hid_crescendo_algorithm_from_id(id: u8) -> Option<crate::KeyAlg> {
    match id {
        0x04 => Some(crate::KeyAlg::Rsa4096),
        0x05 => Some(crate::KeyAlg::Rsa3072),
        0x07 => Some(crate::KeyAlg::Rsa2048),
        0x11 => Some(crate::KeyAlg::EccP256),
        0x14 => Some(crate::KeyAlg::EccP384),
        _ => None,
    }
}

/// The inverse of [`hid_crescendo_algorithm_from_id`]: a [`crate::KeyAlg`]
/// to HID's C4000 algorithm-identifier byte, per the "P1 Reference Control
/// Parameter" table on
/// <https://docs.hidglobal.com/crescendo/api/c4000/inject-pki-key.htm>
/// (`INJECT PKI KEY`'s own P1 encodes the algorithm directly, unlike
/// C2300's coarser RSA/EC-only split — see
/// [`hid_crescendo_c2300_delete_key`]/[`hid_crescendo_c4000_delete_key`]).
/// Same five-entry table as [`hid_crescendo_algorithm_from_id`] — both
/// pages describe the same `PIVCryptographicMechanismIdentifier`-typed
/// field, RSA-4096's `0x04` (not Yubico's `0x16`) included — so this is
/// that function's `id -> KeyAlg` direction run backward rather than a
/// second, independently-sourced table. `None` for
/// [`crate::KeyAlg::Rsa1024`], [`crate::KeyAlg::EccP521`],
/// [`crate::KeyAlg::Ed25519`], and [`crate::KeyAlg::X25519`]: none of the
/// four appear in that P1 table (its EC rows stop at 384 bits — HID has no
/// documented P-521 support on this family), so this crate has no known byte
/// for them on this family. In practice this
/// never fires for a value [`crate::KeyAlg`] round-trips through
/// [`hid_crescendo_algorithm_from_id`] first (as
/// `keyroost_transport::PivSession::hid_crescendo_slot_algorithm` always
/// does before calling [`hid_crescendo_c4000_delete_key`]), since that
/// function can't produce any of the four either — kept total (returning
/// `Option`, not panicking) for a caller that hands this an algorithm from
/// somewhere else.
#[must_use]
pub fn hid_crescendo_c4000_algorithm_id(alg: crate::KeyAlg) -> Option<u8> {
    match alg {
        crate::KeyAlg::Rsa4096 => Some(0x04),
        crate::KeyAlg::Rsa3072 => Some(0x05),
        crate::KeyAlg::Rsa2048 => Some(0x07),
        crate::KeyAlg::EccP256 => Some(0x11),
        crate::KeyAlg::EccP384 => Some(0x14),
        crate::KeyAlg::Rsa1024
        | crate::KeyAlg::EccP521
        | crate::KeyAlg::Ed25519
        | crate::KeyAlg::X25519 => None,
    }
}

/// HID Crescendo C2300's INJECT PKI KEY (`INS D8h`), sent in its
/// degenerate "remove the key" form, per
/// <https://docs.hidglobal.com/crescendo/api/low-level/inject-pki-key.htm>:
///
/// | | CLA | INS | P1 | P2 | Lc | Data | Le |
/// |---|---|---|---|---|---|---|---|
/// | RSA | `80h` | `D8h` | `00h` | `key_ref` | `03h` | `00h 00 A3h 00h`¹ | (absent) |
/// | EC | `80h` | `D8h` | `03h` | `key_ref` | `03h` | `00h B1h 00h`¹ | (absent) |
///
/// ¹ Data field, per the page's "Coding of the Data Field for INJECT PKI
/// RSA/EC KEY" tables:
///
/// | offset | len | value | meaning |
/// |---|---|---|---|
/// | 0 | 1 | `0x00` | RFU |
/// | 1 | 1 | `0xA3` (RSA) / `0xB1` (EC) | Algorithm Identifier |
/// | 2 | 1 | `0x00` | Length of Key Data Value Field |
///
/// P1's bit 7 clear means "last (or only) command" — no chained calls
/// follow, per the page's own P1 bit table — and its low bits are the
/// coarse `00h`(RSA)/`03h`(EC) split that table gives for a non-chained
/// call; C2300 draws no finer distinction between RSA key sizes — or EC
/// curves, [`crate::KeyAlg::EccP521`] included, despite this family's own
/// GENERATE KEY PAIR reference confirming no support for it (see
/// [`crate::compat::PivExtension::SlotKeyAlgorithm`]'s C2300 known-support
/// table) — at this layer, unlike C4000 (see [`hid_crescendo_c4000_delete_key`]),
/// so any RSA [`crate::KeyAlg`] resolves the same `00h`/`0xA3` pair. The Data field's
/// own length rule — both the RSA and EC tables state "0 bytes to remove
/// the corresponding key, in this case the following bytes are absent" for
/// the Length-of-Key-Data field — is what turns an ordinary key-install
/// call into a delete: once that field is `0x00`, everything that would
/// otherwise follow it (the real key-data length, the key value itself, the
/// key check value) is omitted outright, leaving the 3-byte data field
/// above.
///
/// **Not confirmed on live hardware.** The page documents removal only via
/// that one general "zero-length field" rule shared with installation — it
/// gives no literal example APDU for a delete specifically, on either key
/// type. If a live C2300 rejects this, that rule (and this reconstruction
/// of it) is the first thing to re-check against the page.
///
/// `None` for [`crate::KeyAlg::Ed25519`]/[`crate::KeyAlg::X25519`] — neither
/// is a PIV RSA or EC algorithm HID's scheme recognises at all (same
/// unreachable-in-practice caveat as
/// [`hid_crescendo_c4000_algorithm_id`]'s `None` cases).
#[must_use]
pub fn hid_crescendo_c2300_delete_key(alg: crate::KeyAlg, key_ref: u8) -> Option<Vec<u8>> {
    let (p1, alg_id) = match alg {
        crate::KeyAlg::Rsa1024
        | crate::KeyAlg::Rsa2048
        | crate::KeyAlg::Rsa3072
        | crate::KeyAlg::Rsa4096 => (0x00, 0xA3),
        crate::KeyAlg::EccP256 | crate::KeyAlg::EccP384 | crate::KeyAlg::EccP521 => (0x03, 0xB1),
        crate::KeyAlg::Ed25519 | crate::KeyAlg::X25519 => return None,
    };
    Some(vec![0x80, 0xD8, p1, key_ref, 0x03, 0x00, alg_id, 0x00])
}

/// HID Crescendo C4000's INJECT PKI KEY (`INS D8h`), sent in the same
/// degenerate "remove the key" form as [`hid_crescendo_c2300_delete_key`] —
/// see that function's doc for the shared "zero-length Length-of-Key-Data
/// field removes the key" rule both families' API references state
/// identically for RSA and EC — per
/// <https://docs.hidglobal.com/crescendo/api/c4000/inject-pki-key.htm>:
///
/// `80h D8h <alg id> key_ref 03h 00h 00h 00h` (Lc `03h`, Data `00h 00h 00h`, no `Le`)
///
/// Unlike C2300, P1 here is [`hid_crescendo_c4000_algorithm_id`]'s
/// algorithm-specific byte — C4000's P1 table names each RSA size and curve
/// individually rather than C2300's coarse RSA/EC split — so `None`
/// propagates straight through whenever that function has none. The data
/// field's own offset-1 "Algorithm Identifier" byte is a fixed `0x00` here
/// regardless of `alg` (confirmed for EC specifically; assumed to hold for
/// RSA too — see the caveat below): once P1 already names the exact
/// algorithm, `0x00`/`0x03` moves entirely onto P1 and the data-field byte
/// that distinguished RSA from EC on C2300 has nothing left to do. This is
/// distinct from the page's `0xA4`..`0xA8` per-CRT-component identifiers
/// (`p`/`q`/`qInv`/`dP`/`dQ`), which belong to a separate, chained
/// multi-part *installation* scheme (P1 bit 7 set, "more commands follow")
/// this single-call, non-chained removal form has no reason to go through.
///
/// **Not confirmed on live hardware — more so than
/// [`hid_crescendo_c2300_delete_key`].** No C4000 unit has been available
/// to test any part of INJECT PKI KEY yet (same gap
/// `keyroost_piv::compat`'s `GET_METADATA_VERDICTS` C4000 bullet documents
/// for GET PIV PROPERTIES). The EC data field's fixed `0x00` Algorithm
/// Identifier byte is what the page's EC-specific table states outright;
/// the RSA data field is reconstructed by analogy to it, since the page's
/// RSA table only spells out the per-CRT-component chained-install form,
/// never a plain single-call one. If a live C4000 rejects an RSA delete
/// specifically, that analogy is the first thing to re-check.
#[must_use]
pub fn hid_crescendo_c4000_delete_key(alg: crate::KeyAlg, key_ref: u8) -> Option<Vec<u8>> {
    let p1 = hid_crescendo_c4000_algorithm_id(alg)?;
    Some(vec![0x80, 0xD8, p1, key_ref, 0x03, 0x00, 0x00, 0x00])
}

/// Decode a plain-text command response as a `String`: no TLV or other
/// framing at all, just the raw bytes themselves, decoded here as lossy
/// UTF-8. `None` when empty.
#[must_use]
pub fn parse_ascii_text(data: &[u8]) -> Option<String> {
    (!data.is_empty()).then(|| String::from_utf8_lossy(data).into_owned())
}

/// Split a dotted ASCII version string (e.g. `"3.35.0"`) into its numeric
/// components, for `keyroost_transport::PivStatus::version_firmware`.
/// `None` if the string is empty or any component isn't a valid `u8` — a
/// version string this crate can't make sense of is reported as "no
/// firmware version" rather than risking a wrong one.
#[must_use]
pub fn parse_dotted_version(s: &str) -> Option<Vec<u8>> {
    if s.is_empty() {
        return None;
    }
    s.split('.').map(|part| part.parse::<u8>().ok()).collect()
}

/// Token2's own published serial-number-prefix reference for its PIN+ PIV+
/// product line, condensed to just `(prefix, generation)` — the leading 5
/// decimal digits of a unit's full serial, and the synthetic version bytes
/// [`token2_firmware_from_serial`] reports for it —
/// <https://www.token2.com/site/page/pin-firmware-feature-support-matrix-openpgp-fido2-otp-and-piv-across-releases#pin-serial-number-prefix-reference>.
/// Model and branding columns from that page are dropped entirely; nothing
/// in this crate consumes them.
///
/// **Only the `R3.3 (PIV)` and `R3.4 (PIV + OTP Protection)` rows are
/// represented — every earlier revision (Initial/R1, R2, R3, R3.1, R3.2) is
/// left out on purpose, not just unmapped.** This table is only ever
/// consulted once a card has already fingerprinted as a Token2 **PIV**
/// applet at all, and per the vendor's own revision naming no such applet
/// exists before R3.3 — a pre-R3.3 prefix can't actually reach
/// [`token2_firmware_from_serial`] in practice. That also sidesteps the one
/// row on the vendor page that isn't a clean 5-digit prefix (`R3.1`'s
/// "Custom system access card" batch, published as the explicit numeric
/// range `70000001`–`70002000`): it predates R3.3, so it predates PIV
/// entirely and has no business being in a PIV-only lookup regardless of its
/// odd shape.
const TOKEN2_SERIAL_PREFIX_GENERATION: &[(&str, &[u8])] = &[
    // R3.3 (PIV)
    ("66105", &[3, 3]),
    ("66104", &[3, 3]),
    ("66103", &[3, 3]),
    ("66107", &[3, 3]),
    ("66106", &[3, 3]),
    ("66114", &[3, 3]),
    ("66113", &[3, 3]),
    ("66202", &[3, 3]),
    ("66102", &[3, 3]),
    ("66302", &[3, 3]),
    ("66101", &[3, 3]),
    ("66111", &[3, 3]),
    ("72113", &[3, 3]),
    ("24133", &[3, 3]),
    // R3.4 (PIV + OTP Protection)
    ("65103", &[3, 4]),
    ("65104", &[3, 4]),
    ("72114", &[3, 4]),
    ("65101", &[3, 4]),
    ("65111", &[3, 4]),
    ("65202", &[3, 4]),
    ("65102", &[3, 4]),
    ("65302", &[3, 4]),
];

/// Derive a Token2 PIV unit's hardware generation from its full device
/// serial (as read via the on-device OTP applet's `GET_INFO` — see
/// `keyroost_transport::PivSession::probe_token2_otp_serial`; this must be
/// the full serial, not the BCD-truncated 4-byte value the PIV applet's own
/// `GET SERIAL` extension answers with, since that truncation strips exactly
/// the prefix this function keys on), by matching the leading 5 digits of
/// `serial`'s decimal representation against
/// `TOKEN2_SERIAL_PREFIX_GENERATION`.
///
/// The returned bytes are **not** anything Token2's firmware reports
/// itself — they're a fixed encoding this crate assigns to the vendor's own
/// named revisions (`[3, 3]` for R3.3, `[3, 4]` for R3.4), solely so
/// `keyroost_transport::PivStatus::version_firmware`'s existing
/// firmware-version axis has something to hold for a device whose applet
/// never answers a real firmware-version query at all. `serial.to_string()`
/// is used as-is with no leading-zero handling: no prefix in the table
/// starts with `0`, so a genuine Token2 serial can't collide with one that
/// lost a leading zero somewhere upstream.
///
/// `None` when `serial`'s decimal form is shorter than 5 digits, or its
/// prefix isn't in the table — a pre-R3.3 unit (see
/// `TOKEN2_SERIAL_PREFIX_GENERATION`'s doc for why those are absent by
/// construction) or a future revision this table hasn't been updated for.
#[must_use]
pub fn token2_firmware_from_serial(serial: u128) -> Option<&'static [u8]> {
    let text = serial.to_string();
    let prefix = text.get(..5)?;
    TOKEN2_SERIAL_PREFIX_GENERATION
        .iter()
        .find(|(p, _)| *p == prefix)
        .map(|(_, generation)| *generation)
}

/// Decode the hardware variant out of a [`NITROKEY_GET_ADMIN_STATUS`]
/// response: byte offset 4 of the firmware's `AdminStatus::serialize()`
/// layout (init-status flags, IFS block count, EFS block count as
/// big-endian `u16`, then this one variant byte) — see
/// <https://github.com/Nitrokey/nitrokey-3-firmware/blob/main/components/apps/src/lib.rs#L909>
/// (`Variant`: `Usbip = 0`, `Lpc55 = 1`, `Nrf52 = 2`). `None` when the
/// response is shorter than 5 bytes, or the byte names no variant this crate
/// knows (a firmware newer than this table).
#[must_use]
pub fn parse_nitrokey_variant(data: &[u8]) -> Option<&'static str> {
    match data.get(4)? {
        0 => Some("USBIP"),
        1 => Some("LPC55"),
        2 => Some("NRF52"),
        _ => None,
    }
}

/// The display name for
/// [`AppletFingerprint::Trussed`]`(`[`TrussedVariant::NitroKey`]`)` once its
/// hardware variant is known: `"NitroKey (<variant>)"`.
#[must_use]
pub fn format_nitrokey_name(variant: &str) -> String {
    format!("NitroKey ({variant})")
}

/// The display name for [`AppletFingerprint::YubiKey`]: `"Yubico YubiKey
/// <major> Series"`, from the major-version byte (`version[0]`) of the
/// Yubico `GET VERSION` extension reply the transport layer already fetched
/// for `keyroost_transport::PivStatus::version` — this deliberately takes
/// that reply rather than issuing its own GET VERSION, so fingerprinting a
/// YubiKey never sends the command a second time. `None` when the reply is
/// empty (nothing to name a series after).
#[must_use]
pub fn format_yubikey_name(version: &[u8]) -> Option<String> {
    let major = *version.first()?;
    Some(format!("Yubico YubiKey {major} Series"))
}

/// Strip a redundant trailing version off an applet name, when a separately
/// retrieved `version` already covers it.
///
/// If `name` ends in (case-insensitively on the word `Applet`) the pattern
/// `Applet\s+(\d+(?:\.\d+)*)` — the literal word "Applet", one or more
/// whitespace characters, then a dotted run of decimal numbers reaching the
/// very end of the string — and `version` starts with that same numeric
/// sequence, the matched `Applet <version>` suffix (and any whitespace left
/// dangling before it) is redundant with `version` and gets removed. `name`
/// is returned unchanged in every other case: no trailing `Applet <version>`
/// pattern, or `version` doesn't share its prefix.
///
/// HID Crescendo is the motivating case: its SELECT response's Application
/// Label already embeds a truncated applet version (observed on a real
/// C2300: `"HID Global ActivID Applet 3.0.3"`), which its GET PIV PROPERTIES
/// response then reports more precisely (`3.0.3.6`) as this fingerprint's own
/// `version` field — see `keyroost_transport::PivSession::applet_fingerprint`.
/// Once that fuller version is available, repeating a truncated copy of it
/// inside the name is redundant, so it's stripped: `"HID Global ActivID
/// Applet 3.0.3"` + version `[3, 0, 3, 6]` becomes `"HID Global ActivID"`.
#[must_use]
pub fn strip_redundant_applet_version_suffix(name: &str, version: &[u8]) -> String {
    let Some(idx) = name.to_ascii_lowercase().rfind("applet") else {
        return name.to_string();
    };
    let after = &name[idx + "applet".len()..];
    let digits = after.trim_start();
    if digits.len() == after.len() {
        // No whitespace between "Applet" and what follows — \s+ needs at
        // least one.
        return name.to_string();
    }
    let Some(name_version) = parse_dotted_version(digits) else {
        return name.to_string();
    };
    if version.starts_with(name_version.as_slice()) {
        name[..idx].trim_end().to_string()
    } else {
        name.to_string()
    }
}

/// A best-effort fingerprint of the PIV applet implementation behind a
/// session — from ATR/select text, from whether a specific applet can be
/// selected by AID at all, and in general from whether the card supports a
/// particular instruction. `Generic` is the default and the fallback: it
/// means no more specific fingerprint matched, not that fingerprinting
/// failed outright.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AppletFingerprint {
    /// No more specific fingerprint below matched.
    #[default]
    Generic,
    /// Based on <https://github.com/arekinath/PivApplet>.
    ArekinathPivApplet(ArekinathVariant),
    /// Authentrend's ATkey PIV applets — <https://authentrend.com/atkey-card-nfc>.
    AuthentrendATKey,
    /// Feitian Technologies' security keys — recognised purely by whether
    /// the card can select Feitian's registered RID ([`FEITIAN_RID`]): the
    /// "does a specific applet exist" fingerprinting method, rather than an
    /// ATR/select text hint.
    Feitian,
    /// HID's Crescendo product line — <https://www.hidglobal.com/product-mix/crescendo>.
    HidCrescendo(HidCrescendoVariant),
    /// Gemalto/Thales IDPrime PIV cards — recognised purely by whether the
    /// card can select their obscure second PIV applet instance
    /// ([`IDPRIME_SECONDARY_PIV_AID`]): the "does a specific applet exist"
    /// fingerprinting method, rather than an ATR/select text hint.
    IdPrime,
    /// Based on the Trussed applet — <https://github.com/trussed-dev/piv-authenticator>.
    Trussed(TrussedVariant),
    /// Based on <https://github.com/makinako/OpenFIPS201>.
    OpenFips201(OpenFips201Variant),
    /// Thetis' PRO FIDO2 Security Key with PinPlex — recognised by ATR
    /// historical bytes that contain both `"PIV"` and `"8888888"`
    /// (case-insensitively), provided the ATR didn't already fingerprint as
    /// [`AppletFingerprint::Token2`]: Token2's own ATR signature is close
    /// enough to this criterion that checking it alone would misclassify a
    /// Token2 device as Thetis — see
    /// <https://github.com/framefilter/keyroost/issues/125>. [`classify`]
    /// enforces the exclusion by checking the Token2 branch first.
    Thetis,
    /// Token2 PIV products — <https://token2.com/c/piv-devices>.
    Token2,
    /// Identiv/Hirsch's uTrust series — <https://www.hirschsecure.com/germany/en/products>.
    UTrust(UTrustVariant),
    /// Yubico's YubiKey series — <https://www.yubico.com/products/>.
    YubiKey,
}

/// Sub-fingerprint within [`AppletFingerprint::ArekinathPivApplet`].
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArekinathVariant {
    /// No more specific variant matched.
    Generic,
    /// A Swissbit iShield Key running PivApplet — recognised by its ATR
    /// identity ("iShield") on top of the base PivApplet select identity.
    SwissbitIShield1,
}

/// Sub-fingerprint within [`AppletFingerprint::HidCrescendo`].
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HidCrescendoVariant {
    /// Matched via the select identity (`"HID Global ActivID..."`) rather
    /// than a recognised ATR identity — neither [`Self::C2300`] nor
    /// [`Self::C4000`] applies.
    Generic,
    /// ATR identity is `"C2300"`.
    C2300,
    /// ATR identity is `"C4000"`.
    C4000,
}

/// Sub-fingerprint within [`AppletFingerprint::Trussed`].
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrussedVariant {
    /// A Nitrokey running the Trussed `piv-authenticator` — recognised by
    /// its select identity, not its ATR (Nitrokey's ATR doesn't carry a
    /// usable card-issuer-data field; the select identity does).
    NitroKey,
}

/// Sub-fingerprint within [`AppletFingerprint::OpenFips201`].
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenFips201Variant {
    /// No more specific variant matched.
    Generic,
    /// A Swissbit iShield Key running OpenFIPS201 — recognised by whether
    /// Swissbit's own registered RID ([`SWISSBIT_RID`]) can also be
    /// selected on the same card.
    SwissbitIShield2,
}

/// Sub-fingerprint within [`AppletFingerprint::UTrust`].
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UTrustVariant {
    /// Identiv/Hirsch's general-purpose uTrust FIDO2 Security Keys —
    /// <https://www.hirschsecure.com/germany/en/products/security-keys/utrust-fido2-security-keys-nfc-plus>.
    /// The only variant [`classify`] currently produces: every uTrust ATR
    /// match becomes this one, since nothing yet distinguishes the Gov line
    /// from it on the wire.
    Generic,
    /// Identiv/Hirsch's uTrust FIDO2 Gov Security Keys —
    /// <https://www.hirschsecure.com/germany/en/products/security-keys/utrust-fido2-gov-security-keys>.
    /// Per internal documentation
    /// (<https://hirschsecure.atlassian.net/wiki/spaces/FIDO/pages/4395401218/PIV>)
    /// this line has relevant PIV differences from [`Self::Generic`] — e.g.
    /// a different default management key — but nothing in `classify`
    /// distinguishes it yet, so this variant is reserved for future use and
    /// currently unreachable.
    Gov,
}

impl core::fmt::Display for AppletFingerprint {
    /// The identifier form: `Variant` for a unit variant, `Variant::Sub` for
    /// one carrying a sub-fingerprint — e.g. `OpenFips201::SwissbitIShield2`,
    /// matching Rust's own path syntax for a nested enum variant. Not derived
    /// `Debug`'s parentheses, so this reads unambiguously next to the
    /// friendly name from [`AppletFingerprint::applet_name`] wherever both
    /// appear (`keyroostctl piv status`'s `--json` output).
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            AppletFingerprint::Generic => write!(f, "Generic"),
            AppletFingerprint::ArekinathPivApplet(v) => write!(f, "ArekinathPivApplet::{v}"),
            AppletFingerprint::AuthentrendATKey => write!(f, "AuthentrendATKey"),
            AppletFingerprint::Feitian => write!(f, "Feitian"),
            AppletFingerprint::HidCrescendo(v) => write!(f, "HidCrescendo::{v}"),
            AppletFingerprint::IdPrime => write!(f, "IdPrime"),
            AppletFingerprint::Trussed(v) => write!(f, "Trussed::{v}"),
            AppletFingerprint::OpenFips201(v) => write!(f, "OpenFips201::{v}"),
            AppletFingerprint::Thetis => write!(f, "Thetis"),
            AppletFingerprint::Token2 => write!(f, "Token2"),
            AppletFingerprint::UTrust(v) => write!(f, "UTrust::{v}"),
            AppletFingerprint::YubiKey => write!(f, "YubiKey"),
        }
    }
}

impl core::fmt::Display for ArekinathVariant {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            ArekinathVariant::Generic => "Generic",
            ArekinathVariant::SwissbitIShield1 => "SwissbitIShield1",
        })
    }
}

impl core::fmt::Display for HidCrescendoVariant {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            HidCrescendoVariant::Generic => "Generic",
            HidCrescendoVariant::C2300 => "C2300",
            HidCrescendoVariant::C4000 => "C4000",
        })
    }
}

impl core::fmt::Display for TrussedVariant {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            TrussedVariant::NitroKey => "NitroKey",
        })
    }
}

impl core::fmt::Display for OpenFips201Variant {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            OpenFips201Variant::Generic => "Generic",
            OpenFips201Variant::SwissbitIShield2 => "SwissbitIShield2",
        })
    }
}

impl core::fmt::Display for UTrustVariant {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            UTrustVariant::Generic => "Generic",
            UTrustVariant::Gov => "Gov",
        })
    }
}

impl AppletFingerprint {
    /// A generic, human-readable display name for this fingerprint — the
    /// fallback a caller shows when the token didn't report a specific name
    /// of its own (see `keyroost_transport::PivStatus::applet_name`).
    /// Distinct from the [`Display`](core::fmt::Display) impl above, which
    /// renders the variant name(s) rather than a product name (a Swissbit
    /// iShield's `OpenFips201::SwissbitIShield2` vs. this method's
    /// `"Swissbit iShield 2 Series"`).
    #[must_use]
    pub fn applet_name(&self) -> &'static str {
        match self {
            AppletFingerprint::Generic => "Generic PIV",
            AppletFingerprint::ArekinathPivApplet(ArekinathVariant::Generic) => {
                "Generic Arekinath's PivApplet Variant"
            }
            AppletFingerprint::ArekinathPivApplet(ArekinathVariant::SwissbitIShield1) => {
                "Swissbit iShield 1 Series"
            }
            AppletFingerprint::AuthentrendATKey => "Authentrend ATKey Series",
            AppletFingerprint::Feitian => "Feitian Security Key",
            AppletFingerprint::HidCrescendo(HidCrescendoVariant::Generic) => {
                "HID Crescendo ActivId"
            }
            AppletFingerprint::HidCrescendo(HidCrescendoVariant::C2300) => "HID Crescendo C2300",
            AppletFingerprint::HidCrescendo(HidCrescendoVariant::C4000) => "HID Crescendo C4000",
            AppletFingerprint::IdPrime => "IdPrime PIV Series",
            AppletFingerprint::Trussed(TrussedVariant::NitroKey) => "NitroKey",
            AppletFingerprint::OpenFips201(OpenFips201Variant::Generic) => "Generic OpenFIPS201",
            AppletFingerprint::OpenFips201(OpenFips201Variant::SwissbitIShield2) => {
                "Swissbit iShield 2 Series"
            }
            AppletFingerprint::Thetis => "Thetis Series",
            AppletFingerprint::Token2 => "Token2 Series",
            AppletFingerprint::UTrust(UTrustVariant::Generic) => "Identiv/Hirsch uTrust Series",
            AppletFingerprint::UTrust(UTrustVariant::Gov) => "Identiv/Hirsch uTrust Gov Series",
            AppletFingerprint::YubiKey => "Yubico YubiKey Series",
        }
    }
}

/// ISO 7816-3 §8.2.3 historical bytes from a raw ATR (or a PC/SC-synthesised
/// contactless pseudo-ATR): walks past TS, T0, and the TA/TB/TC/TD
/// interface-byte blocks the T0/TD nibbles describe, then returns the
/// trailing `hist_len`-byte block T0's low nibble names. `None` on any
/// structural short-read (truncated ATR) — a malformed ATR just yields no
/// fingerprint rather than a wrong one.
#[must_use]
pub fn atr_historical_bytes(atr: &[u8]) -> Option<&[u8]> {
    let t0 = *atr.get(1)?;
    let hist_len = usize::from(t0 & 0x0F);
    let mut y = t0 >> 4;
    let mut pos = 2usize;
    loop {
        for bit in 0..3 {
            if y & (1 << bit) != 0 {
                atr.get(pos)?;
                pos += 1;
            }
        }
        if y & 0b1000 == 0 {
            break;
        }
        let td = *atr.get(pos)?;
        pos += 1;
        y = td >> 4;
    }
    atr.get(pos..pos + hist_len)
}

/// ISO 7816-4 §8.1.1 COMPACT-TLV objects from a historical-byte region: each
/// object is a header byte `(tag << 4) | len` followed by `len` value bytes.
/// A `0x00` header is padding and ends the run, as does a length that
/// overruns the buffer — either way, whatever parsed cleanly is kept.
fn compact_tlv(mut data: &[u8]) -> Vec<(u8, &[u8])> {
    let mut out = Vec::new();
    while let Some((&head, rest)) = data.split_first() {
        if head == 0x00 {
            break;
        }
        let len = usize::from(head & 0x0F);
        if rest.len() < len {
            break;
        }
        out.push((head >> 4, &rest[..len]));
        data = &rest[len..];
    }
    out
}

/// Decode raw bytes into a `String` one byte per `char` (not UTF-8/lossy
/// decoding) — some historical-byte fields embed a literal NUL as a
/// separator (Token2's "TK\0PIV"), which a lossy UTF-8 decode would leave
/// intact anyway, but this keeps the mapping exact for any non-ASCII byte
/// too rather than substituting a replacement character.
fn bytes_as_chars(raw: &[u8]) -> String {
    raw.iter().map(|&b| b as char).collect()
}

/// The "atr identity" fingerprint text, per keyroost's fingerprinting scheme:
///
/// * category `0x00`/`0x80` (the two COMPACT-TLV historical-byte layouts):
///   the COMPACT-TLV "card issuer's data" object (tag `0x5`) — this is the
///   free-text field ISO 7816-4 reserves for exactly this, and it's where
///   real tokens put a product name (a YubiKey's tag-5 object decodes to
///   literally `"YubiKey"`).
/// * any other category: the entire historical-byte block.
///
/// Both are decoded via `bytes_as_chars`. `None` when there are no
/// historical bytes, or (for the TLV categories) no tag-5 object.
#[must_use]
pub fn atr_identity(historical: &[u8]) -> Option<String> {
    let (&category, rest) = historical.split_first()?;
    let raw: &[u8] = match category {
        0x00 | 0x80 => {
            compact_tlv(rest)
                .into_iter()
                .find(|(tag, _)| *tag == 0x5)?
                .1
        }
        _ => historical,
    };
    (!raw.is_empty()).then(|| bytes_as_chars(raw))
}

/// The "select identity" fingerprint text: ISO 7816-4 tag `0x50` (Application
/// Label), searched recursively through the SELECT response's (possibly
/// nested) constructed BER-TLV structure — vendors disagree on whether it
/// sits directly under the `0x6F` FCI or nested inside a proprietary `0xA5`
/// template, so this doesn't assume either shape. Decoded as lossy UTF-8:
/// unlike ATR issuer data, this field carries vendor+version text
/// (`"PivApplet/1.10"`, `"OpenFIPS201"`, ...), not a fixed-width value that
/// would legitimately embed a NUL. `None` when absent or empty.
#[must_use]
pub fn select_identity(select_response: &[u8]) -> Option<String> {
    let value = crate::find_tlv_recursive(select_response, 0x50)?;
    (!value.is_empty()).then(|| String::from_utf8_lossy(value).into_owned())
}

/// Whether [`classify`] would use a positive `swissbit_rid_selectable` — i.e.
/// whether it's worth the transport layer's spending an extra SELECT/
/// re-SELECT round trip to find out. Only true once the base OpenFIPS201
/// select identity is already present; probing on every card regardless
/// would mean two extra APDUs on every PIV status read for a bit that only
/// ever matters on Swissbit's own firmware.
#[must_use]
pub fn wants_swissbit_probe(select_identity: Option<&str>) -> bool {
    select_identity.is_some_and(|s| s.to_ascii_lowercase().contains("openfips201"))
}

/// Resolve an [`AppletFingerprint`] from the fingerprint text plus the three
/// live-probe bits — all "can a specific applet be selected by AID at all"
/// checks ([`wants_swissbit_probe`]'s [`SWISSBIT_RID`],
/// `feitian_rid_selectable`'s [`FEITIAN_RID`], and `idprime_aid_selectable`'s
/// [`IDPRIME_SECONDARY_PIV_AID`]) — the transport layer can supply. Comparisons are
/// case-insensitive throughout, per the fingerprinting scheme. When more
/// than one fingerprint's criteria are satisfied, the one backed by the most
/// criteria wins — realised here as a priority order from most-specific to
/// least, since with the duplicate uTrust definition dropped no two entries
/// can actually tie. `feitian_rid_selectable` and, after it,
/// `idprime_aid_selectable` sit at the very end of that order: each is the
/// sole criterion for its own identity ([`AppletFingerprint::Feitian`] /
/// [`AppletFingerprint::IdPrime`]), so a caller only needs to have actually
/// performed that probe (an extra SELECT round trip) when every other branch
/// here — including the other one of the two — would otherwise fall through
/// to `Generic`. Passing `false` for a probe that wasn't run is exactly as
/// safe as any other unanswered criterion.
#[must_use]
pub fn classify(
    atr_identity: Option<&str>,
    select_identity: Option<&str>,
    swissbit_rid_selectable: bool,
    feitian_rid_selectable: bool,
    idprime_aid_selectable: bool,
) -> AppletFingerprint {
    let atr = atr_identity.map(str::to_ascii_lowercase);
    let atr = atr.as_deref();
    let sel = select_identity.map(str::to_ascii_lowercase);
    let sel = sel.as_deref();

    // 2 criteria: select identity starts with "PivApplet" AND contains "/".
    let arekinath = sel.is_some_and(|s| s.starts_with("pivapplet") && s.contains('/'));
    // 1 criterion: select identity includes "OpenFIPS201".
    let open_fips_201 = sel.is_some_and(|s| s.contains("openfips201"));
    // 1 criterion: select identity starts with "HID Global ActivID".
    let hid_crescendo_sel = sel.is_some_and(|s| s.starts_with("hid global activid"));

    if arekinath && atr == Some("ishield") {
        // 3 criteria (the 2 above plus the ATR identity).
        AppletFingerprint::ArekinathPivApplet(ArekinathVariant::SwissbitIShield1)
    } else if open_fips_201 && swissbit_rid_selectable {
        // 2 criteria (the 1 above plus the live probe).
        AppletFingerprint::OpenFips201(OpenFips201Variant::SwissbitIShield2)
    } else if arekinath {
        AppletFingerprint::ArekinathPivApplet(ArekinathVariant::Generic)
    } else if atr == Some("c2300") || atr == Some("c4000") || hid_crescendo_sel {
        // The ATR identity picks the variant when it names a recognised
        // model; a match via the select identity alone (neither C2300 nor
        // C4000) is the generic `Generic`.
        AppletFingerprint::HidCrescendo(match atr {
            Some("c2300") => HidCrescendoVariant::C2300,
            Some("c4000") => HidCrescendoVariant::C4000,
            _ => HidCrescendoVariant::Generic,
        })
    } else if sel.is_some_and(|s| s.starts_with("nitrokey")) {
        AppletFingerprint::Trussed(TrussedVariant::NitroKey)
    } else if open_fips_201 {
        AppletFingerprint::OpenFips201(OpenFips201Variant::Generic)
    } else if atr.is_some_and(|a| a.starts_with("tk\0piv") || a.starts_with("tk piv")) {
        AppletFingerprint::Token2
    } else if atr.is_some_and(|a| a.contains("piv") && a.contains("8888888")) {
        AppletFingerprint::Thetis
    } else if atr == Some("utrust") {
        // Nothing on the wire yet distinguishes the Gov line from the
        // generic one — see `UTrustVariant::Gov`'s doc — so every uTrust ATR
        // match becomes `Generic` for now.
        AppletFingerprint::UTrust(UTrustVariant::Generic)
    } else if atr == Some("yubikey") {
        AppletFingerprint::YubiKey
    } else if sel.is_some_and(|s| s.starts_with("atpiv")) {
        AppletFingerprint::AuthentrendATKey
    } else if feitian_rid_selectable {
        AppletFingerprint::Feitian
    } else if idprime_aid_selectable {
        AppletFingerprint::IdPrime
    } else {
        AppletFingerprint::Generic
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- atr_historical_bytes: interface-byte walk ------------------------

    #[test]
    fn historical_bytes_after_no_interface_bytes() {
        // T0 = 0x02: no TA/TB/TC/TD, 2 historical bytes follow immediately.
        let atr = [0x3B, 0x02, 0xAA, 0xBB];
        assert_eq!(atr_historical_bytes(&atr), Some(&[0xAA, 0xBB][..]));
    }

    #[test]
    fn historical_bytes_skip_one_interface_byte() {
        // T0 = 0x1F: y = 1 (TA1 present), hist_len = F = 15... trim to fit.
        // Use a smaller, exact example instead: T0 = 0x12 -> y=1 (TA1), len=2.
        let atr = [0x3B, 0x12, 0x96, 0xAA, 0xBB];
        assert_eq!(atr_historical_bytes(&atr), Some(&[0xAA, 0xBB][..]));
    }

    #[test]
    fn historical_bytes_walk_chained_td_blocks() {
        // T0 = 0x81: y=8 (TD1 present, no TA/TB/TC in block 1), hist_len=1.
        // TD1 = 0x00: protocol 0, y'=0 -> block 2 has nothing, chain ends.
        let atr = [0x3B, 0x81, 0x00, 0xAA];
        assert_eq!(atr_historical_bytes(&atr), Some(&[0xAA][..]));
    }

    #[test]
    fn truncated_atr_yields_none() {
        // T0 claims 4 historical bytes, only 1 is actually present.
        let atr = [0x3B, 0x04, 0xAA];
        assert_eq!(atr_historical_bytes(&atr), None);
        // Missing T0 entirely.
        assert_eq!(atr_historical_bytes(&[0x3B]), None);
    }

    // --- atr_identity: category 0x80 (real YubiKey historical bytes) -----

    #[test]
    fn yubikey_tag5_is_the_atr_identity() {
        // 80 73 C0 21 C0 57 59 75 62 69 4B 65 79 40:
        //   category 0x80, tag-7 card capabilities (C0 21 C0), tag-5 issuer
        //   data "YubiKey" (57 59 75 62 69 4B 65 79 -> len 7), tag-4 empty.
        let hist = [
            0x80, 0x73, 0xC0, 0x21, 0xC0, 0x57, 0x59, 0x75, 0x62, 0x69, 0x4B, 0x65, 0x79, 0x40,
        ];
        assert_eq!(atr_identity(&hist).as_deref(), Some("YubiKey"));
    }

    #[test]
    fn tag5_absent_is_no_identity_for_tlv_categories() {
        // category 0x80, only a tag-7 object — no tag 5 anywhere.
        let hist = [0x80, 0x73, 0xC0, 0x21, 0xC0];
        assert_eq!(atr_identity(&hist), None);
    }

    #[test]
    fn embedded_nul_survives_atr_identity() {
        // category 0x00, tag-5 "TK\0PIV" (6 bytes), no status trailer.
        let hist = [0x00, 0x56, b'T', b'K', 0x00, b'P', b'I', b'V'];
        assert_eq!(atr_identity(&hist).as_deref(), Some("TK\0PIV"));
    }

    #[test]
    fn non_tlv_category_is_the_whole_block_as_chars() {
        // category 0x41 (proprietary) - not 0x00/0x80, so no TLV decode:
        // the whole historical-byte block becomes the identity.
        let hist = [0x41, b'u', b'T', b'r', b'u', b's', b't'];
        assert_eq!(atr_identity(&hist).as_deref(), Some("AuTrust"));
    }

    #[test]
    fn empty_historical_bytes_is_no_identity() {
        assert_eq!(atr_identity(&[]), None);
    }

    // --- select_identity: recursive tag-0x50 search -----------------------

    #[test]
    fn select_identity_at_top_level() {
        // 6F <len> 50 <len> "OpenFIPS201"
        let mut resp = vec![0x6F, 0x0D, 0x50, 0x0B];
        resp.extend_from_slice(b"OpenFIPS201");
        assert_eq!(select_identity(&resp).as_deref(), Some("OpenFIPS201"));
    }

    #[test]
    fn select_identity_nested_under_proprietary_template() {
        // 6F <len> A5 <len> 50 <len> "PivApplet/1.10"
        let label = b"PivApplet/1.10";
        let mut inner = vec![0x50, label.len() as u8];
        inner.extend_from_slice(label);
        let mut resp = vec![0x6F, (inner.len() + 2) as u8, 0xA5, inner.len() as u8];
        resp.extend_from_slice(&inner);
        assert_eq!(select_identity(&resp).as_deref(), Some("PivApplet/1.10"));
    }

    #[test]
    fn select_identity_absent_is_none() {
        let resp = [0x6F, 0x02, 0x84, 0x00];
        assert_eq!(select_identity(&resp), None);
    }

    // --- wants_swissbit_probe -----------------------------------------

    #[test]
    fn probe_only_wanted_for_openfips201() {
        assert!(wants_swissbit_probe(Some("OpenFIPS201")));
        assert!(wants_swissbit_probe(Some("openfips201 v1.0"))); // case-insensitive
        assert!(!wants_swissbit_probe(Some("PivApplet/1.10")));
        assert!(!wants_swissbit_probe(None));
    }

    // --- classify: one case per fingerprint, plus the priority ordering ---

    #[test]
    fn classify_falls_back_to_generic() {
        assert_eq!(
            classify(None, None, false, false, false),
            AppletFingerprint::Generic
        );
        assert_eq!(
            classify(
                Some("something unknown"),
                Some("also unknown"),
                false,
                false,
                false
            ),
            AppletFingerprint::Generic
        );
    }

    #[test]
    fn classify_feitian_only_via_the_rid_probe() {
        // The probe bit alone, no other fingerprinting text, is enough.
        assert_eq!(
            classify(None, None, false, true, false),
            AppletFingerprint::Feitian
        );
        // It's the lowest-priority criterion: any other match wins over it.
        assert_eq!(
            classify(Some("YubiKey"), None, false, true, false),
            AppletFingerprint::YubiKey
        );
        // Without the probe (or a false result from it), an otherwise
        // unidentified card stays Generic.
        assert_eq!(
            classify(None, None, false, false, false),
            AppletFingerprint::Generic
        );
    }

    #[test]
    fn classify_idprime_only_via_the_aid_probe() {
        // The probe bit alone, no other fingerprinting text, is enough.
        assert_eq!(
            classify(None, None, false, false, true),
            AppletFingerprint::IdPrime
        );
        // It's lower priority than even Feitian's own catch-all probe.
        assert_eq!(
            classify(None, None, false, true, true),
            AppletFingerprint::Feitian
        );
        // Without the probe (or a false result from it), an otherwise
        // unidentified card stays Generic.
        assert_eq!(
            classify(None, None, false, false, false),
            AppletFingerprint::Generic
        );
    }

    #[test]
    fn classify_arekinath_any_and_swissbit_variant() {
        assert_eq!(
            classify(None, Some("PivApplet/1.10"), false, false, false),
            AppletFingerprint::ArekinathPivApplet(ArekinathVariant::Generic)
        );
        // Case-insensitive on both fields, and the ATR identity narrows to
        // the Swissbit variant.
        assert_eq!(
            classify(Some("iShield"), Some("pivapplet/2.0"), false, false, false),
            AppletFingerprint::ArekinathPivApplet(ArekinathVariant::SwissbitIShield1)
        );
        // "PivApplet" without a "/" doesn't satisfy the base 2-criteria match.
        assert_eq!(
            classify(None, Some("PivApplet"), false, false, false),
            AppletFingerprint::Generic
        );
    }

    #[test]
    fn classify_authentrend_atkey() {
        assert_eq!(
            classify(None, Some("ATPIV v3"), false, false, false),
            AppletFingerprint::AuthentrendATKey
        );
    }

    #[test]
    fn classify_hid_crescendo_variants_by_atr() {
        assert_eq!(
            classify(Some("C2300"), None, false, false, false),
            AppletFingerprint::HidCrescendo(HidCrescendoVariant::C2300)
        );
        assert_eq!(
            classify(Some("C4000"), None, false, false, false),
            AppletFingerprint::HidCrescendo(HidCrescendoVariant::C4000)
        );
    }

    #[test]
    fn classify_hid_crescendo_any_via_select_identity_alone() {
        // Matched via the select identity, with an ATR that names neither
        // recognised model (or none at all) — the generic `Generic` variant.
        assert_eq!(
            classify(None, Some("HID Global ActivID PIV"), false, false, false),
            AppletFingerprint::HidCrescendo(HidCrescendoVariant::Generic)
        );
        assert_eq!(
            classify(
                Some("something else"),
                Some("HID Global ActivID PIV"),
                false,
                false,
                false
            ),
            AppletFingerprint::HidCrescendo(HidCrescendoVariant::Generic)
        );
    }

    #[test]
    fn classify_trussed_nitrokey() {
        // Select identity, not ATR identity — Nitrokey's ATR is ignored.
        assert_eq!(
            classify(
                None,
                Some("Nitrokey PIV Authenticator"),
                false,
                false,
                false
            ),
            AppletFingerprint::Trussed(TrussedVariant::NitroKey)
        );
        assert_eq!(
            classify(Some("Nitrokey"), None, false, false, false),
            AppletFingerprint::Generic
        );
    }

    #[test]
    fn classify_openfips201_any_and_swissbit_variant() {
        assert_eq!(
            classify(None, Some("OpenFIPS201"), false, false, false),
            AppletFingerprint::OpenFips201(OpenFips201Variant::Generic)
        );
        assert_eq!(
            classify(None, Some("OpenFIPS201"), true, false, false),
            AppletFingerprint::OpenFips201(OpenFips201Variant::SwissbitIShield2)
        );
        // The probe bit alone (no OpenFIPS201 select identity) matches nothing.
        assert_eq!(
            classify(None, None, true, false, false),
            AppletFingerprint::Generic
        );
    }

    #[test]
    fn classify_token2_either_spelling() {
        assert_eq!(
            classify(Some("TK\0PIV v1"), None, false, false, false),
            AppletFingerprint::Token2
        );
        assert_eq!(
            classify(Some("TK PIV v1"), None, false, false, false),
            AppletFingerprint::Token2
        );
    }

    #[test]
    fn classify_thetis_needs_both_substrings_case_insensitively() {
        assert_eq!(
            classify(Some("PIV 8888888"), None, false, false, false),
            AppletFingerprint::Thetis
        );
        // Case-insensitive on the ATR identity, same as every other branch.
        assert_eq!(
            classify(Some("piv 8888888"), None, false, false, false),
            AppletFingerprint::Thetis
        );
        // Either substring alone isn't enough.
        assert_eq!(
            classify(Some("PIV only"), None, false, false, false),
            AppletFingerprint::Generic
        );
        assert_eq!(
            classify(Some("8888888 only"), None, false, false, false),
            AppletFingerprint::Generic
        );
    }

    #[test]
    fn token2_r3_3_historical_bytes_are_not_misclassified_as_thetis() {
        // Real ATR historical bytes from a Token2 R3.3+ device: "TK\0PIV"
        // (the signature `classify`'s Token2 branch matches on), followed by
        // a 2-byte version and, coincidentally, "8888888" — the very
        // substring `classify`'s Thetis branch looks for. This is the exact
        // collision documented on `AppletFingerprint::Thetis` and
        // <https://github.com/framefilter/keyroost/issues/125>: were the
        // Thetis branch checked first (or independently of the Token2
        // branch), this ATR would misclassify as Thetis.
        let historical = [
            0x54, 0x4B, 0x00, 0x50, 0x49, 0x56, 0x04, 0x02, 0x38, 0x38, 0x38, 0x38, 0x38, 0x38,
            0x38,
        ];
        let identity = atr_identity(&historical);
        assert_eq!(identity.as_deref(), Some("TK\0PIV\u{4}\u{2}8888888"));
        assert_eq!(
            classify(identity.as_deref(), None, false, false, false),
            AppletFingerprint::Token2
        );
    }

    #[test]
    fn classify_utrust_and_yubikey() {
        assert_eq!(
            classify(Some("uTrust"), None, false, false, false),
            AppletFingerprint::UTrust(UTrustVariant::Generic)
        );
        assert_eq!(
            classify(Some("YubiKey"), None, false, false, false),
            AppletFingerprint::YubiKey
        );
    }

    #[test]
    fn applet_name_matches_the_display_name_table() {
        // Pins the exact generic display name for every constructible value,
        // so a future variant added without a matching arm fails to
        // compile, not just fails a test.
        let cases = [
            (AppletFingerprint::Generic, "Generic PIV"),
            (
                AppletFingerprint::ArekinathPivApplet(ArekinathVariant::Generic),
                "Generic Arekinath's PivApplet Variant",
            ),
            (
                AppletFingerprint::ArekinathPivApplet(ArekinathVariant::SwissbitIShield1),
                "Swissbit iShield 1 Series",
            ),
            (
                AppletFingerprint::AuthentrendATKey,
                "Authentrend ATKey Series",
            ),
            (AppletFingerprint::Feitian, "Feitian Security Key"),
            (
                AppletFingerprint::HidCrescendo(HidCrescendoVariant::Generic),
                "HID Crescendo ActivId",
            ),
            (
                AppletFingerprint::HidCrescendo(HidCrescendoVariant::C2300),
                "HID Crescendo C2300",
            ),
            (
                AppletFingerprint::HidCrescendo(HidCrescendoVariant::C4000),
                "HID Crescendo C4000",
            ),
            (AppletFingerprint::IdPrime, "IdPrime PIV Series"),
            (
                AppletFingerprint::Trussed(TrussedVariant::NitroKey),
                "NitroKey",
            ),
            (
                AppletFingerprint::OpenFips201(OpenFips201Variant::Generic),
                "Generic OpenFIPS201",
            ),
            (
                AppletFingerprint::OpenFips201(OpenFips201Variant::SwissbitIShield2),
                "Swissbit iShield 2 Series",
            ),
            (AppletFingerprint::Thetis, "Thetis Series"),
            (AppletFingerprint::Token2, "Token2 Series"),
            (
                AppletFingerprint::UTrust(UTrustVariant::Generic),
                "Identiv/Hirsch uTrust Series",
            ),
            (
                AppletFingerprint::UTrust(UTrustVariant::Gov),
                "Identiv/Hirsch uTrust Gov Series",
            ),
            (AppletFingerprint::YubiKey, "Yubico YubiKey Series"),
        ];
        for (id, expected) in cases {
            assert_eq!(id.applet_name(), expected);
        }
    }

    // --- Display: Rust-style `::` for sub-identities, not Debug's parens --

    #[test]
    fn display_uses_a_double_colon_for_sub_identities() {
        assert_eq!(AppletFingerprint::Generic.to_string(), "Generic");
        assert_eq!(
            AppletFingerprint::OpenFips201(OpenFips201Variant::SwissbitIShield2).to_string(),
            "OpenFips201::SwissbitIShield2"
        );
        assert_eq!(
            AppletFingerprint::ArekinathPivApplet(ArekinathVariant::Generic).to_string(),
            "ArekinathPivApplet::Generic"
        );
        assert_eq!(
            AppletFingerprint::Trussed(TrussedVariant::NitroKey).to_string(),
            "Trussed::NitroKey"
        );
        assert_eq!(
            AppletFingerprint::HidCrescendo(HidCrescendoVariant::C4000).to_string(),
            "HidCrescendo::C4000"
        );
        assert_eq!(
            AppletFingerprint::UTrust(UTrustVariant::Gov).to_string(),
            "UTrust::Gov"
        );
        assert_eq!(AppletFingerprint::Feitian.to_string(), "Feitian");
        assert_eq!(AppletFingerprint::IdPrime.to_string(), "IdPrime");
        assert_eq!(AppletFingerprint::Thetis.to_string(), "Thetis");
        assert_eq!(AppletFingerprint::YubiKey.to_string(), "YubiKey");
    }

    // --- plain-text response decoding ---------------------------------------

    #[test]
    fn ascii_text_decodes_plain_text() {
        // No TLV framing at all — the Nitrokey admin app's firmware reply.
        let fw = b"3.35.0";
        assert_eq!(parse_ascii_text(fw).as_deref(), Some("3.35.0"));
    }

    #[test]
    fn ascii_text_empty_is_none() {
        assert_eq!(parse_ascii_text(&[]), None);
    }

    // --- Nitrokey admin status: hardware variant byte -----------------------

    #[test]
    fn nitrokey_variant_reads_offset_4() {
        // init_status, ifs_blocks, efs_blocks (2 bytes BE), variant.
        assert_eq!(
            parse_nitrokey_variant(&[0x00, 0x10, 0x00, 0x20, 0x00]),
            Some("USBIP")
        );
        assert_eq!(
            parse_nitrokey_variant(&[0x00, 0x10, 0x00, 0x20, 0x01]),
            Some("LPC55")
        );
        assert_eq!(
            parse_nitrokey_variant(&[0x00, 0x10, 0x00, 0x20, 0x02]),
            Some("NRF52")
        );
    }

    #[test]
    fn nitrokey_variant_unknown_byte_or_short_response_is_none() {
        assert_eq!(
            parse_nitrokey_variant(&[0x00, 0x10, 0x00, 0x20, 0x03]),
            None
        );
        assert_eq!(parse_nitrokey_variant(&[0x00, 0x10, 0x00, 0x20]), None); // 4 bytes, no offset 4
        assert_eq!(parse_nitrokey_variant(&[]), None);
    }

    #[test]
    fn format_nitrokey_name_wraps_the_variant() {
        assert_eq!(format_nitrokey_name("NRF52"), "NitroKey (NRF52)");
    }

    // --- YubiKey display name from the already-fetched GET VERSION reply --

    #[test]
    fn format_yubikey_name_uses_the_major_version_byte() {
        assert_eq!(
            format_yubikey_name(&[5, 7, 4]).as_deref(),
            Some("Yubico YubiKey 5 Series")
        );
        assert_eq!(
            format_yubikey_name(&[4, 3, 7]).as_deref(),
            Some("Yubico YubiKey 4 Series")
        );
    }

    #[test]
    fn format_yubikey_name_empty_reply_is_none() {
        assert_eq!(format_yubikey_name(&[]), None);
    }

    // --- redundant "Applet <version>" suffix stripping ----------------------

    #[test]
    fn strip_applet_suffix_when_version_starts_with_the_named_one() {
        assert_eq!(
            strip_redundant_applet_version_suffix("HID Global ActivID Applet 3.0.3", &[3, 0, 3, 6],),
            "HID Global ActivID"
        );
    }

    #[test]
    fn strip_applet_suffix_is_case_insensitive_on_the_word_applet() {
        assert_eq!(
            strip_redundant_applet_version_suffix("Some Name APPLET 3.0.3", &[3, 0, 3]),
            "Some Name"
        );
    }

    #[test]
    fn strip_applet_suffix_kept_when_version_does_not_match_prefix() {
        // Same number of segments, but they diverge — not a prefix match.
        assert_eq!(
            strip_redundant_applet_version_suffix("HID Global ActivID Applet 3.0.3", &[3, 0, 4]),
            "HID Global ActivID Applet 3.0.3"
        );
    }

    #[test]
    fn strip_applet_suffix_kept_when_no_applet_word_present() {
        assert_eq!(
            strip_redundant_applet_version_suffix("Yubico YubiKey 5 Series", &[5, 4, 3]),
            "Yubico YubiKey 5 Series"
        );
    }

    #[test]
    fn strip_applet_suffix_kept_when_applet_has_no_trailing_version() {
        assert_eq!(
            strip_redundant_applet_version_suffix("Foo Applet", &[3, 0, 3]),
            "Foo Applet"
        );
    }

    #[test]
    fn strip_applet_suffix_kept_when_trailing_text_is_not_purely_dotted_digits() {
        assert_eq!(
            strip_redundant_applet_version_suffix("Foo Applet 3.0.3-beta", &[3, 0, 3]),
            "Foo Applet 3.0.3-beta"
        );
    }

    #[test]
    fn strip_applet_suffix_requires_whitespace_right_after_applet() {
        assert_eq!(
            strip_redundant_applet_version_suffix("Foo Applet3.0.3", &[3, 0, 3]),
            "Foo Applet3.0.3"
        );
    }

    // --- dotted version string -> byte components --------------------------

    #[test]
    fn dotted_version_splits_numeric_components() {
        assert_eq!(parse_dotted_version("3.35.0"), Some(vec![3, 35, 0]));
        assert_eq!(parse_dotted_version("1.2.3"), Some(vec![1, 2, 3]));
        // A single component (no dot) is still a valid one-element version.
        assert_eq!(parse_dotted_version("5"), Some(vec![5]));
    }

    #[test]
    fn dotted_version_rejects_empty_or_non_numeric() {
        assert_eq!(parse_dotted_version(""), None);
        assert_eq!(parse_dotted_version("a.b.c"), None);
        assert_eq!(parse_dotted_version("3..0"), None); // empty component
                                                        // A component that doesn't fit in a u8 makes the whole thing
                                                        // unparsable rather than silently truncating it.
        assert_eq!(parse_dotted_version("3.999.0"), None);
    }

    // --- Token2 serial prefix -> hardware generation ------------------------

    #[test]
    fn token2_firmware_from_serial_matches_r3_3_and_r3_4_prefixes() {
        // R3.3 (PIV): USB-A NFC PIN+ PIV+, branded.
        assert_eq!(
            token2_firmware_from_serial(66105_1234567_u128),
            Some(&[3, 3][..])
        );
        // R3.4 (PIV + OTP Protection): PIN+ Dual Ace, unbranded.
        assert_eq!(
            token2_firmware_from_serial(65104_7654321_u128),
            Some(&[3, 4][..])
        );
    }

    #[test]
    fn token2_firmware_from_serial_rejects_unrecognised_or_short_serial() {
        // A well-formed but unknown prefix (no row on either R3.3 or R3.4).
        assert_eq!(token2_firmware_from_serial(99999_0000000_u128), None);
        // A pre-R3.3 prefix (R1's `86105`) is deliberately absent — no PIV
        // applet exists on that hardware to ever call this in practice, but
        // a prefix that did somehow reach this function still resolves to
        // `None` like any other unrecognised one, rather than panicking.
        assert_eq!(token2_firmware_from_serial(86105_0000000_u128), None);
        // Fewer than 5 digits: nothing to match a prefix against.
        assert_eq!(token2_firmware_from_serial(1234_u128), None);
    }

    // --- HID Crescendo C2300: GET PIV PROPERTIES ----------------------------

    /// Build a synthetic `53 <len> [51 <len> 48 01 <key_ref> 43 04 <alg_id>
    /// 00 01 01]*` response — one `0x51` block per `(key_ref, alg_id)` pair,
    /// each with a 4-byte `0x43` (the C2300 length, one shorter than C4000's
    /// documented 5).
    fn c2300_properties_response(slots: &[(u8, u8)]) -> Vec<u8> {
        let mut inner = Vec::new();
        for &(key_ref, alg_id) in slots {
            let block = [0x48, 0x01, key_ref, 0x43, 0x04, alg_id, 0x00, 0x01, 0x01];
            inner.push(0x51);
            inner.push(block.len() as u8);
            inner.extend_from_slice(&block);
        }
        let mut resp = vec![0x53, inner.len() as u8];
        resp.extend_from_slice(&inner);
        resp
    }

    /// Same shape, but with C4000's documented 5-byte `0x43` (an extra
    /// trailing "Key Purpose" byte C2300 doesn't have).
    fn c4000_properties_response(slots: &[(u8, u8)]) -> Vec<u8> {
        let mut inner = Vec::new();
        for &(key_ref, alg_id) in slots {
            let block = [
                0x48, 0x01, key_ref, 0x43, 0x05, alg_id, 0x00, 0x01, 0x01, 0x00,
            ];
            inner.push(0x51);
            inner.push(block.len() as u8);
            inner.extend_from_slice(&block);
        }
        let mut resp = vec![0x53, inner.len() as u8];
        resp.extend_from_slice(&inner);
        resp
    }

    #[test]
    fn c2300_properties_decodes_every_slot_from_one_response() {
        let resp = c2300_properties_response(&[(0x9A, 0x07), (0x9C, 0x11), (0x9E, 0x14)]);
        assert_eq!(
            parse_hid_crescendo_slot_key_algorithms(&resp),
            vec![(0x9A, 0x07), (0x9C, 0x11), (0x9E, 0x14)]
        );
    }

    #[test]
    fn c4000_shaped_properties_decode_the_same_way_as_c2300() {
        // The one documented structural difference (`0x43` one byte longer)
        // doesn't affect decoding, since only `0x43`'s first byte is read
        // either way — the same function handles both families' replies.
        let resp = c4000_properties_response(&[(0x9A, 0x07), (0x9D, 0x11)]);
        assert_eq!(
            parse_hid_crescendo_slot_key_algorithms(&resp),
            vec![(0x9A, 0x07), (0x9D, 0x11)]
        );
    }

    #[test]
    fn c2300_properties_skips_a_block_missing_a_subtag_keeps_the_rest() {
        // The first block has no `0x43` subtag at all (malformed/short) — it
        // is skipped, not fatal to the other, well-formed block.
        let bad_block = [0x48, 0x01, 0x9A];
        let good_block = [0x48, 0x01, 0x9C, 0x43, 0x04, 0x14, 0x00, 0x01, 0x01];
        let mut inner = vec![0x51, bad_block.len() as u8];
        inner.extend_from_slice(&bad_block);
        inner.push(0x51);
        inner.push(good_block.len() as u8);
        inner.extend_from_slice(&good_block);
        let mut resp = vec![0x53, inner.len() as u8];
        resp.extend_from_slice(&inner);
        assert_eq!(
            parse_hid_crescendo_slot_key_algorithms(&resp),
            vec![(0x9C, 0x14)]
        );
    }

    #[test]
    fn c2300_properties_ignores_non_0x51_top_level_tags() {
        // A `0x39`/`0x3A`/`0x50` neighbor tag, as HID's own documented
        // response shape has, doesn't confuse the walk.
        let mut inner = vec![0x39, 0x01, 0xAA];
        let block = [0x48, 0x01, 0x9A, 0x43, 0x04, 0x07, 0x00, 0x01, 0x01];
        inner.push(0x51);
        inner.push(block.len() as u8);
        inner.extend_from_slice(&block);
        inner.extend_from_slice(&[0x45, 0x01, 0xBB]);
        let mut resp = vec![0x53, inner.len() as u8];
        resp.extend_from_slice(&inner);
        assert_eq!(
            parse_hid_crescendo_slot_key_algorithms(&resp),
            vec![(0x9A, 0x07)]
        );
    }

    #[test]
    fn properties_tolerates_a_missing_0x53_wrapper() {
        // HID's C4000 API reference describes the response's top-level tags
        // directly, without ever mentioning a `0x53` wrapper the way the
        // C2300 reference does — so an unwrapped reply is still decoded
        // rather than rejected outright.
        let block = [0x48, 0x01, 0x9A, 0x43, 0x04, 0x07, 0x00, 0x01, 0x01];
        let mut resp = vec![0x51, block.len() as u8];
        resp.extend_from_slice(&block);
        assert_eq!(
            parse_hid_crescendo_slot_key_algorithms(&resp),
            vec![(0x9A, 0x07)]
        );
    }

    #[test]
    fn c2300_properties_empty_data_object_is_an_empty_vec() {
        assert_eq!(
            parse_hid_crescendo_slot_key_algorithms(&[0x53, 0x00]),
            vec![]
        );
    }

    #[test]
    fn properties_block_with_no_key_loaded_is_excluded() {
        // Both private and public key initialization status are `0x00`
        // ("not initialized") — the PKI container is allocated (the `0x51`
        // block exists) but no key was ever generated or injected into it,
        // so this slot must not be reported at all, regardless of the
        // algorithm byte it happens to carry.
        let block = [0x48, 0x01, 0x9A, 0x43, 0x04, 0x07, 0x20, 0x00, 0x00];
        let mut inner = vec![0x51, block.len() as u8];
        inner.extend_from_slice(&block);
        let mut resp = vec![0x53, inner.len() as u8];
        resp.extend_from_slice(&inner);
        assert_eq!(parse_hid_crescendo_slot_key_algorithms(&resp), vec![]);
    }

    #[test]
    fn properties_block_is_included_when_either_status_byte_is_nonzero() {
        // Private generated, public still not initialized — a key exists.
        let generated = [0x48, 0x01, 0x9A, 0x43, 0x04, 0x07, 0x20, 0x01, 0x00];
        // Private not initialized, public injected — still a key.
        let injected = [0x48, 0x01, 0x9C, 0x43, 0x04, 0x07, 0x20, 0x00, 0x81];
        let mut inner = vec![0x51, generated.len() as u8];
        inner.extend_from_slice(&generated);
        inner.push(0x51);
        inner.push(injected.len() as u8);
        inner.extend_from_slice(&injected);
        let mut resp = vec![0x53, inner.len() as u8];
        resp.extend_from_slice(&inner);
        assert_eq!(
            parse_hid_crescendo_slot_key_algorithms(&resp),
            vec![(0x9A, 0x07), (0x9C, 0x07)]
        );
    }

    // --- HID Crescendo: does GET PIV PROPERTIES report a given slot at ------
    // --- all, regardless of key-load status ----------------------------------

    #[test]
    fn reports_slot_true_for_a_present_block_even_with_no_key_loaded() {
        // Both status bytes `0x00` — `parse_hid_crescendo_slot_key_algorithms`
        // would exclude this block entirely, but `hid_crescendo_reports_slot`
        // only cares that the block names key ref `0x9B` at all.
        let resp = c2300_properties_response(&[]);
        let block = [0x48, 0x01, 0x9B, 0x43, 0x04, 0x00, 0x00, 0x00, 0x00];
        let mut inner = vec![0x51, block.len() as u8];
        inner.extend_from_slice(&block);
        let mut resp2 = vec![0x53, inner.len() as u8];
        resp2.extend_from_slice(&inner);
        assert!(hid_crescendo_reports_slot(&resp2, 0x9B));
        // Sanity: the empty-slots fixture above genuinely has no such block.
        assert!(!hid_crescendo_reports_slot(&resp, 0x9B));
    }

    #[test]
    fn reports_slot_false_when_key_ref_is_absent() {
        let resp = c2300_properties_response(&[(0x9A, 0x07), (0x9C, 0x11)]);
        assert!(hid_crescendo_reports_slot(&resp, 0x9A));
        assert!(!hid_crescendo_reports_slot(&resp, 0x9B));
    }

    #[test]
    fn reports_slot_works_on_c4000_shaped_responses_too() {
        let resp = c4000_properties_response(&[(0x9B, 0x03)]);
        assert!(hid_crescendo_reports_slot(&resp, 0x9B));
        assert!(!hid_crescendo_reports_slot(&resp, 0x9A));
    }

    #[test]
    fn reports_slot_tolerates_a_missing_0x53_wrapper() {
        let block = [0x48, 0x01, 0x9B, 0x43, 0x04, 0x07, 0x00, 0x01, 0x01];
        let mut resp = vec![0x51, block.len() as u8];
        resp.extend_from_slice(&block);
        assert!(hid_crescendo_reports_slot(&resp, 0x9B));
    }

    #[test]
    fn reports_slot_empty_data_object_is_false() {
        assert!(!hid_crescendo_reports_slot(&[0x53, 0x00], 0x9B));
    }

    // --- GlobalPlatform CPLC: on-card printed serial number -----------------

    #[test]
    fn cplc_serial_decodes_fabricator_type_batch_serial_in_that_order() {
        // IC Fabricator=0x1234, IC Type=0x5678, OS ID/date/level/fab-date
        // (unused, all zero), IC Serial Number=0x00090009 (8 digits with
        // leading zeros), IC Batch Identifier=0x4321.
        let mut cplc = vec![0x12, 0x34, 0x56, 0x78, 0, 0, 0, 0, 0, 0, 0, 0];
        cplc.extend_from_slice(&[0x00, 0x09, 0x00, 0x09]); // IC Serial Number
        cplc.extend_from_slice(&[0x43, 0x21]); // IC Batch Identifier
                                               // Fabricator "1234" + Type "5678" + Batch "4321" + Serial "00090009".
        assert_eq!(parse_cplc_serial(&cplc), Some(1234_5678_4321_0009_0009));
    }

    #[test]
    fn cplc_serial_unwraps_a_9f7f_tlv_reply() {
        let mut cplc = vec![0x12, 0x34, 0x56, 0x78, 0, 0, 0, 0, 0, 0, 0, 0];
        cplc.extend_from_slice(&[0x00, 0x09, 0x00, 0x09]);
        cplc.extend_from_slice(&[0x43, 0x21]);
        cplc.extend_from_slice(&[0; 24]); // pad to the full 42-byte structure
        let mut wrapped = vec![0x9F, 0x7F, cplc.len() as u8];
        wrapped.extend_from_slice(&cplc);
        assert_eq!(parse_cplc_serial(&wrapped), parse_cplc_serial(&cplc));
    }

    #[test]
    fn cplc_serial_none_when_too_short() {
        // 17 bytes — one short of reaching IC Batch Identifier (offset 16..18).
        assert_eq!(parse_cplc_serial(&[0u8; 17]), None);
    }

    #[test]
    fn cplc_serial_none_on_a_non_decimal_nibble() {
        let mut cplc = vec![0u8; 18];
        cplc[0] = 0xAB; // nibble 0xA is not a decimal digit
        assert_eq!(parse_cplc_serial(&cplc), None);
    }

    // --- ACA (Access Control Applet) XAUTH byte layer -----------------------

    #[test]
    fn aca_aid_matches_hids_documented_select_example() {
        // `00A4040007A0000000791000` from HID's own XAUTH documentation.
        let apdu = crate::select_by_aid(&HID_CRESCENDO_ACA_AID);
        assert_eq!(
            apdu[..5],
            [0x00, 0xA4, 0x04, 0x00, HID_CRESCENDO_ACA_AID.len() as u8]
        );
        assert_eq!(
            &apdu[5..5 + HID_CRESCENDO_ACA_AID.len()],
            &HID_CRESCENDO_ACA_AID
        );
    }

    #[test]
    fn xauth_key_alg_matches_get_challenge_response_length() {
        assert_eq!(
            hid_crescendo_xauth_key_alg(8),
            Some(crate::MgmtAlg::TripleDes)
        );
        assert_eq!(
            hid_crescendo_xauth_key_alg(16),
            Some(crate::MgmtAlg::Aes128)
        );
        assert_eq!(hid_crescendo_xauth_key_alg(0), None);
        assert_eq!(hid_crescendo_xauth_key_alg(24), None);
    }

    #[test]
    fn external_authenticate_frames_a_tdes_cryptogram() {
        // `0084000108 <8 bytes>` — Lc = 0x08 for an 8-byte TDES cryptogram.
        let cryptogram = [0xE7, 0x90, 0x75, 0xFB, 0xE7, 0xCB, 0xE9, 0x2B];
        let apdu = hid_crescendo_aca_external_authenticate(&cryptogram);
        assert_eq!(
            apdu,
            vec![0x00, 0x82, 0x00, 0x01, 0x08, 0xE7, 0x90, 0x75, 0xFB, 0xE7, 0xCB, 0xE9, 0x2B]
        );
    }

    #[test]
    fn external_authenticate_frames_an_aes128_cryptogram() {
        // `0084000110 <16 bytes>` — Lc = 0x10 for a 16-byte AES-128 cryptogram.
        let cryptogram = [0xAC; 16];
        let apdu = hid_crescendo_aca_external_authenticate(&cryptogram);
        assert_eq!(apdu[..5], [0x00, 0x82, 0x00, 0x01, 0x10]);
        assert_eq!(&apdu[5..], &cryptogram);
    }

    #[test]
    fn put_xauth_key_frames_a_tdes_key() {
        let key = [0x11u8; 24];
        let apdu = hid_crescendo_aca_put_xauth_key(crate::MgmtAlg::TripleDes, &key).unwrap();
        // CLA D8 P1=01 P2=00 Lc=1D (29 bytes: RFU, alg, len-indicator, real
        // len, 24-byte key, check-value len).
        assert_eq!(apdu[..5], [0x00, 0xD8, 0x01, 0x00, 0x1D]);
        assert_eq!(apdu[5], 0x00); // RFU
        assert_eq!(apdu[6], 0x03); // TDES ECB, same as MgmtAlg::TripleDes.id()
        assert_eq!(apdu[7], 0x19); // key data length indicator (24 + 1)
        assert_eq!(apdu[8], 0x18); // real key length (24)
        assert_eq!(&apdu[9..33], &key);
        assert_eq!(apdu[33], 0x00); // key check value length
        assert_eq!(apdu.len(), 5 + 0x1D);
    }

    #[test]
    fn put_xauth_key_frames_an_aes128_key() {
        let key = [0x22u8; 16];
        let apdu = hid_crescendo_aca_put_xauth_key(crate::MgmtAlg::Aes128, &key).unwrap();
        // Lc=15 (21 bytes: RFU, alg, len-indicator, real len, 16-byte key,
        // check-value len).
        assert_eq!(apdu[..5], [0x00, 0xD8, 0x01, 0x00, 0x15]);
        assert_eq!(apdu[6], 0x08); // 128-AES ECB, same as MgmtAlg::Aes128.id()
        assert_eq!(apdu[7], 0x11); // key data length indicator (16 + 1)
        assert_eq!(apdu[8], 0x10); // real key length (16)
        assert_eq!(&apdu[9..25], &key);
        assert_eq!(apdu[25], 0x00);
        assert_eq!(apdu.len(), 5 + 0x15);
    }

    #[test]
    fn put_xauth_key_rejects_unsupported_algorithm_or_wrong_length() {
        // ACA XAUTH only ever supports TDES/AES-128 — Aes192/Aes256 aren't
        // valid here even at a plausible-looking length.
        assert!(hid_crescendo_aca_put_xauth_key(crate::MgmtAlg::Aes192, &[0u8; 24]).is_none());
        assert!(hid_crescendo_aca_put_xauth_key(crate::MgmtAlg::Aes256, &[0u8; 32]).is_none());
        // Right algorithm, wrong key length.
        assert!(hid_crescendo_aca_put_xauth_key(crate::MgmtAlg::TripleDes, &[0u8; 16]).is_none());
        assert!(hid_crescendo_aca_put_xauth_key(crate::MgmtAlg::Aes128, &[0u8; 24]).is_none());
    }

    #[test]
    fn put_xauth_key_remove_frames_the_documented_four_byte_short_form() {
        // CLA D8 P1=01 P2=00 Lc=04, then RFU=0x00, algorithm=0x03 (TDES,
        // unconditional — see this function's doc), length-indicator=0x00,
        // real-key-length=0x00 — no key value, no check-value-length byte,
        // matching HID's documented Lc=04h "remove" case exactly.
        assert_eq!(
            hid_crescendo_aca_put_xauth_key_remove(),
            vec![0x00, 0xD8, 0x01, 0x00, 0x04, 0x00, 0x03, 0x00, 0x00]
        );
    }

    #[test]
    fn reset_card_is_the_documented_case_1_apdu() {
        assert_eq!(HID_CRESCENDO_ACA_RESET_CARD, [0x00, 0x38, 0x00, 0x00]);
    }

    #[test]
    fn factory_xauth_key_is_24_zero_bytes_and_builds_a_valid_put_xauth_key() {
        assert_eq!(HID_CRESCENDO_ACA_FACTORY_XAUTH_KEY, [0u8; 24]);
        // Matches TripleDes's key_len() exactly, so building the restore
        // APDU from it can never hit the None branch in practice.
        assert!(hid_crescendo_aca_put_xauth_key(
            crate::MgmtAlg::TripleDes,
            &HID_CRESCENDO_ACA_FACTORY_XAUTH_KEY
        )
        .is_some());
    }

    #[test]
    fn c2300_version_strips_the_leading_family_byte() {
        // `21 03 00 03 06`: family `0x21`, version `3.0.3.6`.
        let mut resp = vec![0x53, 0x07, 0x01, 0x05];
        resp.extend_from_slice(&[0x21, 0x03, 0x00, 0x03, 0x06]);
        assert_eq!(parse_hid_crescendo_version(&resp), Some(vec![3, 0, 3, 6]));
    }

    #[test]
    fn c2300_version_family_byte_alone_is_an_empty_version() {
        // A tag `0x01` value of just the family byte, no version segments at
        // all — `split_first` still succeeds, leaving an empty remainder.
        let resp = vec![0x53, 0x03, 0x01, 0x01, 0x21];
        assert_eq!(parse_hid_crescendo_version(&resp), Some(vec![]));
    }

    #[test]
    fn c2300_version_absent_is_none() {
        assert_eq!(parse_hid_crescendo_version(&[0x53, 0x00]), None);
    }

    #[test]
    fn c2300_version_empty_tag_value_is_none() {
        // Tag `0x01` present but with a zero-length value — nothing to
        // split a family byte off of.
        let resp = vec![0x53, 0x02, 0x01, 0x00];
        assert_eq!(parse_hid_crescendo_version(&resp), None);
    }

    #[test]
    fn c2300_version_no_tag_0x01_and_no_0x53_wrapper_is_none() {
        // Not a `0x53` object, so treated as already-unwrapped discretionary
        // data (the tolerant fallback) — but that data has no top-level tag
        // `0x01` either, so this is still `None`, just via a different path
        // than a rejected unwrap.
        assert_eq!(parse_hid_crescendo_version(&[0x70, 0x00]), None);
    }

    #[test]
    fn c2300_properties_and_version_decode_a_real_device_response() {
        // A live Crescendo C2300's actual GET PIV PROPERTIES reply (SW 90 00
        // trimmed off) — 5 allocated PKI containers (9A/9C/9D/82/83, each
        // `0x43` reading `07 20 00 00`: algorithm id 0x07, key length 0x20,
        // but private/public init status both `0x00`), no PKI object for 9E
        // at all, and applet version family `0x21`, version `3.0.3.6`. None
        // of the five containers actually has a key loaded — confirmed by
        // the same trace's certificate reads, every one of which came back
        // empty (`53 00` / `6A 82`) — so this is the "container exists, key
        // status says otherwise" case this function's doc describes, and
        // the real reason it must return an empty list here despite five
        // `0x51` blocks being present.
        let resp: [u8; 188] = [
            0x53, 0x81, 0xB9, 0x01, 0x05, 0x21, 0x03, 0x00, 0x03, 0x06, 0x39, 0x01, 0x15, 0x3A,
            0x07, 0xA0, 0x00, 0x00, 0x00, 0x79, 0x10, 0x00, 0x3B, 0x00, 0x50, 0x0C, 0x47, 0x03,
            0x5F, 0xC1, 0x02, 0x26, 0x01, 0x03, 0x42, 0x02, 0x68, 0x0B, 0x50, 0x0C, 0x47, 0x03,
            0x5F, 0xC1, 0x09, 0x26, 0x01, 0x01, 0x42, 0x02, 0xF8, 0x00, 0x50, 0x0C, 0x47, 0x03,
            0x5F, 0xC1, 0x0C, 0x26, 0x01, 0x01, 0x42, 0x02, 0x0A, 0x00, 0x51, 0x15, 0x47, 0x03,
            0x5F, 0xC1, 0x05, 0x26, 0x01, 0x01, 0x48, 0x01, 0x9A, 0x43, 0x04, 0x07, 0x20, 0x00,
            0x00, 0x42, 0x02, 0x75, 0x07, 0x51, 0x15, 0x47, 0x03, 0x5F, 0xC1, 0x0A, 0x26, 0x01,
            0x01, 0x48, 0x01, 0x9C, 0x43, 0x04, 0x07, 0x20, 0x00, 0x00, 0x42, 0x02, 0x75, 0x07,
            0x51, 0x15, 0x47, 0x03, 0x5F, 0xC1, 0x0B, 0x26, 0x01, 0x01, 0x48, 0x01, 0x9D, 0x43,
            0x04, 0x07, 0x20, 0x00, 0x00, 0x42, 0x02, 0x75, 0x07, 0x51, 0x15, 0x47, 0x03, 0x5F,
            0xC1, 0x0D, 0x26, 0x01, 0x01, 0x48, 0x01, 0x82, 0x43, 0x04, 0x07, 0x20, 0x00, 0x00,
            0x42, 0x02, 0x75, 0x07, 0x51, 0x15, 0x47, 0x03, 0x5F, 0xC1, 0x0E, 0x26, 0x01, 0x01,
            0x48, 0x01, 0x83, 0x43, 0x04, 0x07, 0x20, 0x00, 0x00, 0x42, 0x02, 0x75, 0x07, 0x45,
            0x05, 0xD6, 0x88, 0x83, 0x80, 0x00,
        ];
        assert_eq!(parse_hid_crescendo_slot_key_algorithms(&resp), vec![]);
        assert_eq!(parse_hid_crescendo_version(&resp), Some(vec![3, 0, 3, 6]));
    }

    #[test]
    fn hid_crescendo_algorithm_from_id_covers_the_documented_table() {
        assert_eq!(
            hid_crescendo_algorithm_from_id(0x04),
            Some(crate::KeyAlg::Rsa4096)
        );
        assert_eq!(
            hid_crescendo_algorithm_from_id(0x05),
            Some(crate::KeyAlg::Rsa3072)
        );
        assert_eq!(
            hid_crescendo_algorithm_from_id(0x07),
            Some(crate::KeyAlg::Rsa2048)
        );
        assert_eq!(
            hid_crescendo_algorithm_from_id(0x11),
            Some(crate::KeyAlg::EccP256)
        );
        assert_eq!(
            hid_crescendo_algorithm_from_id(0x14),
            Some(crate::KeyAlg::EccP384)
        );
        assert_eq!(hid_crescendo_algorithm_from_id(0xFF), None);
    }

    #[test]
    fn hid_crescendo_c4000_algorithm_id_is_the_exact_inverse_of_from_id() {
        for id in [0x04, 0x05, 0x07, 0x11, 0x14] {
            let alg = hid_crescendo_algorithm_from_id(id).unwrap();
            assert_eq!(hid_crescendo_c4000_algorithm_id(alg), Some(id));
        }
        assert_eq!(
            hid_crescendo_c4000_algorithm_id(crate::KeyAlg::Rsa1024),
            None
        );
        assert_eq!(
            hid_crescendo_c4000_algorithm_id(crate::KeyAlg::EccP521),
            None
        );
        assert_eq!(
            hid_crescendo_c4000_algorithm_id(crate::KeyAlg::Ed25519),
            None
        );
        assert_eq!(
            hid_crescendo_c4000_algorithm_id(crate::KeyAlg::X25519),
            None
        );
    }

    #[test]
    fn hid_crescendo_c2300_delete_key_rsa_frames_the_generic_rsa_alg_id() {
        // Every RSA size shares the same `00h` P1 / `0xA3` Algorithm
        // Identifier pair on C2300 — no per-size distinction at this layer.
        for alg in [
            crate::KeyAlg::Rsa1024,
            crate::KeyAlg::Rsa2048,
            crate::KeyAlg::Rsa3072,
            crate::KeyAlg::Rsa4096,
        ] {
            assert_eq!(
                hid_crescendo_c2300_delete_key(alg, 0x9A),
                Some(vec![0x80, 0xD8, 0x00, 0x9A, 0x03, 0x00, 0xA3, 0x00]),
                "{alg:?}"
            );
        }
    }

    #[test]
    fn hid_crescendo_c2300_delete_key_ec_frames_the_generic_ec_alg_id() {
        // EccP521 folds into the same coarse EC pair as the other two curves
        // — C2300's delete-key framing doesn't distinguish by curve, only
        // RSA vs. EC — even though this family has no confirmed GENERATE
        // KEY PAIR support for it (a different axis; see
        // `HID_CRESCENDO_C2300_APPLET_VERDICTS` in `compat`).
        for (alg, key_ref) in [
            (crate::KeyAlg::EccP256, 0x9C),
            (crate::KeyAlg::EccP384, 0x9D),
            (crate::KeyAlg::EccP521, 0x9E),
        ] {
            assert_eq!(
                hid_crescendo_c2300_delete_key(alg, key_ref),
                Some(vec![0x80, 0xD8, 0x03, key_ref, 0x03, 0x00, 0xB1, 0x00]),
                "{alg:?}"
            );
        }
    }

    #[test]
    fn hid_crescendo_c2300_delete_key_rejects_algorithms_hid_does_not_recognise() {
        assert_eq!(
            hid_crescendo_c2300_delete_key(crate::KeyAlg::Ed25519, 0x9A),
            None
        );
        assert_eq!(
            hid_crescendo_c2300_delete_key(crate::KeyAlg::X25519, 0x9A),
            None
        );
    }

    #[test]
    fn hid_crescendo_c4000_delete_key_frames_the_algorithm_specific_p1() {
        for (alg, p1) in [
            (crate::KeyAlg::Rsa4096, 0x04),
            (crate::KeyAlg::Rsa3072, 0x05),
            (crate::KeyAlg::Rsa2048, 0x07),
            (crate::KeyAlg::EccP256, 0x11),
            (crate::KeyAlg::EccP384, 0x14),
        ] {
            assert_eq!(
                hid_crescendo_c4000_delete_key(alg, 0x9E),
                Some(vec![0x80, 0xD8, p1, 0x9E, 0x03, 0x00, 0x00, 0x00]),
                "{alg:?}"
            );
        }
    }

    #[test]
    fn hid_crescendo_c4000_delete_key_rejects_algorithms_with_no_known_p1() {
        assert_eq!(
            hid_crescendo_c4000_delete_key(crate::KeyAlg::Rsa1024, 0x9A),
            None
        );
        assert_eq!(
            hid_crescendo_c4000_delete_key(crate::KeyAlg::EccP521, 0x9A),
            None
        );
        assert_eq!(
            hid_crescendo_c4000_delete_key(crate::KeyAlg::Ed25519, 0x9A),
            None
        );
        assert_eq!(
            hid_crescendo_c4000_delete_key(crate::KeyAlg::X25519, 0x9A),
            None
        );
    }
}
