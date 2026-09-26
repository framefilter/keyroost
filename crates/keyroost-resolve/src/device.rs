//! Shared device model: one physical key correlated from its FIDO-HID node(s)
//! and PC/SC reader(s), with a capability union and a Molto2-vs-key
//! classification. Consumed by both the GUI and the CLI so they never drift.

use std::path::PathBuf;

use keyroost_hid::HidDevice;
use keyroost_keyring::Keyring;
use keyroost_transport::{ReaderProbe, YubiKeyCcid};

/// Capability bit-set. Hand-rolled (no `bitflags` dep). Each physical key
/// advertises the union of the applets it answers.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct Caps(u8);

impl Caps {
    pub const FIDO2: Caps = Caps(1 << 0);
    pub const OATH: Caps = Caps(1 << 1);
    pub const PGP: Caps = Caps(1 << 2);
    pub const PIV: Caps = Caps(1 << 3);
    pub const TOTP: Caps = Caps(1 << 4); // Molto2 programmable token
    pub const OTP: Caps = Caps(1 << 5); // Token2 FIDO key on-device OTP applet
    pub const PROG: Caps = Caps(1 << 6); // Token2 single-profile programmable token

    pub fn has(self, c: Caps) -> bool {
        self.0 & c.0 != 0
    }
    pub fn insert(&mut self, c: Caps) {
        self.0 |= c.0;
    }
    pub fn is_empty(self) -> bool {
        self.0 == 0
    }
}

/// How well a capability on a [`Device`] is known. `Caps` alone is a bitset —
/// present or absent, with nowhere to record "we could not check" — so on a
/// USB-HID-only enumeration absence of evidence used to be written down as
/// absence of the feature (the whole of the v0.7.7 OTP argument, #82 → #95).
/// This is the third state.
///
/// The behaviour rule: **`Unverified` always behaves as "offer the surface"**
/// (the capability bit is set in [`Device::caps`], exactly the pre-existing
/// fail-open behaviour). The tri-state changes what is *said*, not what is
/// offered — an attempt against an unverified surface produces the real
/// answer, which is a decent message rather than a silent guess.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapState {
    /// The device itself answered: the applet responded to a real `SELECT`
    /// over PC/SC, or (for FIDO2) the FIDO-HID node is the evidence.
    Present,
    /// Not offered. Either the card channel declined the applet's `SELECT`
    /// (probed absence), or keyroost had no channel to ask over and no
    /// label-grade reason to offer the surface. Never derived from a
    /// product-id table (standing decision: no device→capability matrix).
    Absent,
    /// Nothing was asked of the device, but the surface is offered anyway on
    /// a label-grade hint (today: the Token2 vendor id offering OTP, exactly
    /// as `has_otp = is_token2` always did). Rendered distinctly so an offer
    /// is never mistaken for verified presence.
    Unverified,
}

/// What kind of physical device this is. `Token` is the Molto2 family;
/// `ProgToken` is the single-profile programmable token; everything else is a
/// `Key`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceKind {
    Key,
    Token,
    ProgToken,
}

/// A stable identity for a device across refreshes (effective serial, else reader
/// name, else hidraw path).
pub type DeviceId = String;

/// One physical device: the union of its FIDO-HID node and PC/SC applets.
#[derive(Clone)]
pub struct Device {
    pub id: DeviceId,
    pub name: Option<String>,
    pub vendor: String,
    pub model: String,
    pub serial: String,
    pub transport: String,
    pub firmware: String,
    pub caps: Caps,
    /// The subset of `caps` that keyroost could not verify against the device
    /// (no card channel answered a `SELECT` for it) — offered on a label-grade
    /// hint only. Invariant: `unverified` ⊆ `caps`, so every `caps.has(..)`
    /// caller keeps today's fail-open behaviour untouched; consult
    /// [`Device::cap_state`] for the honest per-capability answer.
    pub unverified: Caps,
    pub kind: DeviceKind,
    pub hid_path: Option<PathBuf>,
    pub reader: Option<String>,
}

impl Device {
    /// The tri-state answer for one capability: [`CapState::Present`] when the
    /// device answered for it, [`CapState::Unverified`] when it is offered
    /// without device evidence, [`CapState::Absent`] otherwise.
    pub fn cap_state(&self, c: Caps) -> CapState {
        if !self.caps.has(c) {
            CapState::Absent
        } else if self.unverified.has(c) {
            CapState::Unverified
        } else {
            CapState::Present
        }
    }

    /// Ordered capability badge labels — the shared vocabulary used by the CLI
    /// overview/list and the GUI pills, so they cannot drift. A Token shows a
    /// single "TOTP token" badge; a Key shows one per applet it answers.
    pub fn cap_badges(&self) -> Vec<&'static str> {
        self.cap_badge_states()
            .into_iter()
            .map(|(l, _)| l)
            .collect()
    }

    /// [`Device::cap_badges`] with each badge's [`CapState`] attached, for
    /// surfaces that render unverified capabilities distinctly. Only offered
    /// capabilities appear, so every state here is `Present` or `Unverified`.
    pub fn cap_badge_states(&self) -> Vec<(&'static str, CapState)> {
        if self.kind == DeviceKind::Token {
            return vec![("TOTP token", CapState::Present)];
        }
        let mut v = Vec::new();
        for (c, label) in [
            (Caps::FIDO2, "FIDO2"),
            (Caps::OATH, "OATH"),
            (Caps::PGP, "PGP"),
            (Caps::PIV, "PIV"),
            (Caps::OTP, "OTP"),
        ] {
            if self.caps.has(c) {
                v.push((label, self.cap_state(c)));
            }
        }
        v
    }
}

/// The vendor name for a PC/SC-reader device: the OpenPGP manufacturer ID
/// mapped through the registry when known (card-content identity, #83), else
/// the first word of the reader name (the pre-existing guess), else "Key".
fn card_vendor(openpgp_manufacturer: Option<u16>, reader_name: &str) -> String {
    if let Some(name) = openpgp_manufacturer.and_then(keyroost_openpgp::manufacturer_name) {
        return name.to_string();
    }
    reader_name
        .split_whitespace()
        .next()
        .unwrap_or("Key")
        .to_string()
}

/// Map a USB vendor id to a display name; unknown ids fall back to a generic label.
fn vendor_name(vid: u16) -> &'static str {
    match vid {
        0x1050 => "Yubico",
        0x20a0 => "Nitrokey",
        0x1209 => "SoloKeys",
        0x096e | 0x311f => "Feitian",
        0x2581 => "Kanokey",
        0x349e => "Token2",
        0x1e0d => "OpenSK",
        _ => "Security key",
    }
}

/// Turn a raw PC/SC reader name or USB product name into a clean model label,
/// stripping bracketed groups, interface-noise tokens, a leading vendor word, and
/// trailing two-digit pcsc index groups.
fn clean_model(raw: &str, vendor: &str) -> String {
    let mut s = String::with_capacity(raw.len());
    let mut depth = 0i32;
    for ch in raw.chars() {
        match ch {
            '[' | '(' => depth += 1,
            ']' | ')' => depth = (depth - 1).max(0),
            _ if depth == 0 => s.push(ch),
            _ => {}
        }
    }
    for junk in [
        "CCID/ICCD Interface",
        "OTP+FIDO+CCID",
        "FIDO+CCID",
        "OTP+FIDO",
        "U2F+CCID",
        "+CCID",
        "ICCD",
        "CCID",
        "Interface",
        "Smartcard",
        "Smart Card",
    ] {
        s = s.replace(junk, " ");
    }
    let lead = s.trim_start();
    if !vendor.is_empty()
        && lead
            .to_ascii_lowercase()
            .starts_with(&vendor.to_ascii_lowercase())
    {
        s = lead[vendor.len()..].to_string();
    }
    let mut parts: Vec<&str> = s.split_whitespace().collect();
    while parts.len() > 1 {
        let last = parts[parts.len() - 1];
        if last.len() == 2 && last.chars().all(|c| c.is_ascii_digit()) {
            parts.pop();
        } else {
            break;
        }
    }
    let out = parts.join(" ");
    if out.is_empty() {
        vendor.to_string()
    } else {
        out
    }
}

/// True when some FIDO HID node shares this reader's USB topology (bus+address) —
/// i.e. they are the same physical device. Used to keep a Token2 *FIDO key* from
/// ever being classified as a Molto2 (the Molto2 has no FIDO HID interface).
fn has_fido_hid_sibling(p: &ReaderProbe, hids: &[&HidDevice]) -> bool {
    match (p.usb_bus, p.usb_address) {
        (Some(bus), Some(addr)) => hids
            .iter()
            .any(|h| h.usb_bus == Some(bus) && h.usb_address == Some(addr)),
        _ => false,
    }
}

/// True when a reader plausibly belongs to a Yubico key: it answered the YubiKey
/// serial applet, or its name carries the YubiKey hint. Every non-Molto2 reader
/// is a *possible* CCID sibling, but only these are candidates for the
/// topology-free fallback — an unrelated reader (a built-in laptop slot, a PIV
/// card in a generic reader) is never a Yubico key's own reader.
fn is_yubico_reader(c: &YubiKeyCcid) -> bool {
    c.serial.is_some() || c.reader_name.to_ascii_lowercase().contains("yubikey")
}

/// True when `reader` may still be bound by this HID node. A reader belongs to
/// exactly one physical device, so once a node has claimed it only a node at the
/// *same* USB bus+address — another interface of that very device — may share
/// it. Without this, two keys fuse into one row whose card operations go to one
/// device and whose FIDO operations go to another.
fn reader_is_bindable(
    claimed: &std::collections::HashMap<String, (Option<u8>, Option<u8>)>,
    reader: &str,
    hid: &HidDevice,
) -> bool {
    match claimed.get(reader) {
        None => true,
        Some(&(bus, addr)) => bus.is_some() && bus == hid.usb_bus && addr == hid.usb_address,
    }
}

/// The reader this HID node shares a USB bus+address with — the strongest
/// correlation signal available, and unambiguous even with several same-vendor
/// keys plugged in (#51). `None` when either side reports no topology.
fn reader_by_topology<'a>(probes: &'a [ReaderProbe], hid: &HidDevice) -> Option<&'a ReaderProbe> {
    probes.iter().filter(|p| !p.is_molto2).find(|p| {
        p.usb_bus.is_some() && p.usb_bus == hid.usb_bus && p.usb_address == hid.usb_address
    })
}

/// The reader this HID node can only *guess* at, by vendor: for Yubico the sole
/// plausible YubiKey reader, otherwise the sole reader whose name carries the
/// node's vendor word. Callers must have established that no topology match was
/// possible — a node that reported its own bus+address and matched nothing has
/// positive evidence it is a different physical device and must never guess.
fn reader_by_vendor(
    probes: &[ReaderProbe],
    yk_readers: &[YubiKeyCcid],
    hid: &HidDevice,
) -> Option<String> {
    if hid.vendor_id == crate::VID_YUBICO {
        let cands: Vec<&YubiKeyCcid> = yk_readers.iter().filter(|c| is_yubico_reader(c)).collect();
        return match cands.as_slice() {
            [only] => Some(only.reader_name.clone()),
            _ => None,
        };
    }
    let vt = vendor_name(hid.vendor_id).to_ascii_lowercase();
    let matches: Vec<&str> = probes
        .iter()
        .filter(|p| !p.is_molto2)
        .map(|p| p.reader_name.as_str())
        .filter(|r| r.to_ascii_lowercase().contains(&vt))
        .collect();
    match matches.as_slice() {
        [only] => Some((*only).to_string()),
        _ => None,
    }
}

/// Decide which reader (if any) each FIDO HID node owns, by *strength of
/// evidence* rather than enumeration order. Returns one entry per node, parallel
/// to `hids`.
///
/// Pass 1 hands every reader to the node that matches it on exact USB
/// bus+address. Pass 2 lets the vendor guess take only what pass 1 left over, so
/// a weak name-only match can never claim a reader ahead of the node that proved
/// it is that reader's own sibling — which is how card operations ended up on one
/// physical key while FIDO operations went to another, under a single row. Pass 2
/// also fails closed when two nodes guess the same reader: an unresolvable tie
/// binds nobody rather than whoever the backend happened to enumerate first.
///
/// Deterministic: both passes walk `hids` and `probes` in slice order; the
/// `claimed` map is only ever looked up by key, never iterated.
fn bind_readers(
    hids: &[&HidDevice],
    probes: &[ReaderProbe],
    yk_readers: &[YubiKeyCcid],
) -> Vec<Option<String>> {
    let mut bound: Vec<Option<String>> = vec![None; hids.len()];
    // Readers already bound, keyed by reader name and carrying the claiming
    // node's USB topology (see `reader_is_bindable`).
    let mut claimed: std::collections::HashMap<String, (Option<u8>, Option<u8>)> =
        std::collections::HashMap::new();

    for (i, hid) in hids.iter().enumerate() {
        if let Some(p) = reader_by_topology(probes, hid) {
            if reader_is_bindable(&claimed, &p.reader_name, hid) {
                claimed.insert(p.reader_name.clone(), (hid.usb_bus, hid.usb_address));
                bound[i] = Some(p.reader_name.clone());
            }
        }
    }

    for (i, hid) in hids.iter().enumerate() {
        // Already paired on hard evidence, or it reported its own bus/address and
        // matched no reader — positive evidence it is a different physical
        // device. Only backends that report no topology at all (usb_bus is None —
        // hidapi on Windows and macOS) may guess, or correlation breaks there.
        if bound[i].is_some() || hid.usb_bus.is_some() {
            continue;
        }
        let Some(name) = reader_by_vendor(probes, yk_readers, hid)
            .filter(|n| reader_is_bindable(&claimed, n, hid))
        else {
            continue;
        };
        // Fail closed on contention: with no topology on either side, several
        // same-vendor nodes are *equally* good guesses for the one reader, and
        // one of them is a FIDO-only key that has no card interface at all. The
        // guess would then be pure enumeration order, and a wrong bind is not a
        // cosmetic error — it points every FIDO operation on that row (PIN
        // change, credential deletion, authenticatorReset) at a key the user did
        // not select. Bind none of them and let the card and the FIDO node show
        // as separate rows, exactly as they do when a reader is absent.
        let contended = hids.iter().enumerate().any(|(j, h)| {
            j != i
                && bound[j].is_none()
                && h.usb_bus.is_none()
                && reader_by_vendor(probes, yk_readers, h).as_deref() == Some(name.as_str())
        });
        if contended {
            continue;
        }
        claimed.insert(name.clone(), (hid.usb_bus, hid.usb_address));
        bound[i] = Some(name);
    }
    bound
}

/// Correlate FIDO-HID nodes and PC/SC reader probes into one device per physical
/// key. Pure: all I/O is done by the caller ([`enumerate`]). The `hids` slice may
/// contain non-FIDO nodes; they are filtered here.
pub fn correlate(hids: &[HidDevice], probes: &[ReaderProbe], keyring: &Keyring) -> Vec<Device> {
    let hids: Vec<&HidDevice> = hids.iter().filter(|h| h.is_fido()).collect();

    let yk_readers: Vec<YubiKeyCcid> = probes
        .iter()
        .filter(|p| !p.is_molto2)
        .map(|p| YubiKeyCcid {
            reader_name: p.reader_name.clone(),
            usb_bus: p.usb_bus,
            usb_address: p.usb_address,
            serial: p.yubikey_serial.clone(),
        })
        .collect();

    // Whole-set attribution: the single-reader fallback is refused when several
    // topology-free nodes could each own that reader, so a FIDO-only key can
    // never inherit another key's CCID serial (which would also defeat the
    // re-check that a reset is talking to the key the user picked).
    let serials: Vec<Option<String>> = hids
        .iter()
        .zip(crate::ccid_serials_for(&hids, &yk_readers))
        .map(|(h, s)| h.serial_number.clone().or(s))
        .collect();

    // Serials duplicated across the live HID set are NOT unique identity: two
    // keys that advertise the same serial must stay distinct (KEY-015). Track
    // them so the serial-only merge below is suppressed for them.
    let dup_serials: std::collections::HashSet<String> = {
        let mut seen: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
        for s in serials.iter().flatten() {
            *seen.entry(s.as_str()).or_default() += 1;
        }
        seen.into_iter()
            .filter(|(_, n)| *n > 1)
            .map(|(s, _)| s.to_string())
            .collect()
    };

    let mut devices: Vec<Device> = Vec::new();

    // --- 1. Molto2 tokens — only when there is NO FIDO HID sibling (#21 guard).
    for p in probes
        .iter()
        .filter(|p| p.is_molto2 && !has_fido_hid_sibling(p, &hids))
    {
        let serial = p.serial.clone().unwrap_or_default();
        let mut caps = Caps::default();
        caps.insert(Caps::TOTP);
        devices.push(Device {
            id: format!("molto:{}", p.reader_name),
            name: keyring.name_for(Some(&serial)).map(str::to_owned),
            vendor: "Token2".into(),
            model: "Molto2".into(),
            serial,
            transport: "USB · PC/SC".into(),
            firmware: String::new(),
            caps,
            unverified: Caps::default(),
            kind: DeviceKind::Token,
            hid_path: None,
            reader: Some(p.reader_name.clone()),
        });
    }

    // --- 1b. Single-profile programmable tokens — flagged by their info
    // response during the probe (no applet, no distinctive reader name).
    for p in probes.iter().filter(|p| p.is_prog) {
        let serial = p.prog_serial.clone().unwrap_or_default();
        let model = keyroost_token2prog::model_for_serial(&serial)
            .unwrap_or("Programmable token")
            .to_string();
        let mut caps = Caps::default();
        caps.insert(Caps::PROG);
        devices.push(Device {
            id: format!("prog:{}", p.reader_name),
            name: keyring.name_for(Some(&serial)).map(str::to_owned),
            vendor: "Token2".into(),
            model,
            serial,
            transport: "NFC · PC/SC".into(),
            firmware: String::new(),
            caps,
            unverified: Caps::default(),
            kind: DeviceKind::ProgToken,
            hid_path: None,
            reader: Some(p.reader_name.clone()),
        });
    }

    // --- 2. Smart-card keys, one per non-Molto reader that answers an applet.
    for p in probes.iter().filter(|p| !p.is_molto2) {
        let mut caps = Caps::default();
        if p.has_oath {
            caps.insert(Caps::OATH);
        }
        if p.has_openpgp {
            caps.insert(Caps::PGP);
        }
        if p.has_piv {
            caps.insert(Caps::PIV);
        }
        if p.has_fido {
            caps.insert(Caps::FIDO2);
        }
        if p.has_otp {
            caps.insert(Caps::OTP);
        }
        if caps.is_empty() {
            continue;
        }
        let serial = p
            .yubikey_serial
            .clone()
            .or_else(|| p.serial.clone())
            .unwrap_or_default();
        let id = if serial.is_empty() {
            format!("reader:{}", p.reader_name)
        } else {
            format!("serial:{serial}")
        };
        let vendor = if p.yubikey_serial.is_some() {
            "Yubico".to_string()
        } else {
            card_vendor(p.openpgp_manufacturer, &p.reader_name)
        };
        let model = clean_model(&p.reader_name, &vendor);
        devices.push(Device {
            id,
            name: keyring.name_for(Some(&serial)).map(str::to_owned),
            vendor,
            model,
            serial,
            transport: "USB · PC/SC".into(),
            firmware: String::new(),
            // Every capability on this row came from a real SELECT over the
            // reader — ground truth, nothing unverified.
            caps,
            unverified: Caps::default(),
            kind: DeviceKind::Key,
            hid_path: None,
            reader: Some(p.reader_name.clone()),
        });
    }

    // --- 3. Merge FIDO HID nodes into their physical key. Reader ownership is
    // settled up front by strength of evidence, not enumeration order.
    let bound = bind_readers(&hids, probes, &yk_readers);
    for (i, hid) in hids.iter().enumerate() {
        let serial = serials.get(i).cloned().flatten().unwrap_or_default();
        let is_token2 = hid.vendor_id == keyroost_proto::USB_VID;
        // Every Token2 key is offered the OTP surface, on purpose.
        //
        // v0.7.7 narrowed this to product ids whose vendor function set lists
        // OTP, to stop offering it to keys that have no such applet (issue
        // #82). Token2 then corrected the premise in issue #95: Bio3 (0x0204)
        // **has** OTP — carried over CCID — even though its function set reads
        // FIDO+PGP, because the key has no HOTP-over-HID and ships with the HID
        // channel disabled. So a function set that omits OTP does not mean the
        // applet is absent; it may simply live on a channel this enumeration
        // cannot see. `TOKEN2_PRODUCTS` says as much itself: "nothing here may
        // be treated as proof that an applet is present" — and the inverse is
        // no safer.
        //
        // The v0.7.7 gate therefore hid OTP from Bio3 keys that have it, which
        // is the failure this comment already warned against: hiding an applet
        // a key really has is worse than showing one that turns out to be
        // absent. That trade is now cheaper still, because a key without the
        // applet no longer dead-ends in a raw protocol error — it reports which
        // channel declined and what to do about it.
        //
        // Do not re-narrow this on the PID table without Token2 confirming what
        // a function set actually asserts about applet presence per channel.
        let has_otp = is_token2;
        let reader_name: Option<String> = bound.get(i).cloned().flatten();

        let existing = devices.iter_mut().find(|d| {
            d.kind == DeviceKind::Key
                && ((reader_name.is_some() && d.reader == reader_name)
                    || (!serial.is_empty() && !dup_serials.contains(&serial) && d.serial == serial))
        });
        if let Some(dev) = existing {
            // The HID node itself is the evidence for FIDO2 — verified.
            dev.caps.insert(Caps::FIDO2);
            // OTP: if the reader already answered the applet's SELECT it is
            // verified present and stays so. If the probe did NOT answer for
            // it, the vendor hint still offers the surface (insert-only, a
            // real probe always wins) — but honestly, as unverified: per #95
            // the applet may live on a channel the probe cannot see, so a
            // declined SELECT is not proof of absence, and nothing was proven
            // present either.
            if has_otp && !dev.caps.has(Caps::OTP) {
                dev.caps.insert(Caps::OTP);
                dev.unverified.insert(Caps::OTP);
            }
            dev.hid_path = Some(hid.path.clone());
            dev.transport = "USB · PC/SC + FIDO HID".into();
            if dev.serial.is_empty() {
                dev.serial = serial.clone();
            }
            if dev.name.is_none() {
                dev.name = keyring.name_for(Some(&serial)).map(str::to_owned);
            }
        } else {
            let id = if !serial.is_empty() {
                format!("serial:{serial}")
            } else {
                format!("hid:{}", hid.path.display())
            };
            let mut caps = Caps::default();
            let mut unverified = Caps::default();
            caps.insert(Caps::FIDO2);
            if has_otp {
                // No reader bound: nothing has been asked of this key over a
                // card channel. The vendor id is a label-grade hint that the
                // surface should be offered (exactly the has_otp rule above),
                // not evidence — record it as unverified, never as presence.
                caps.insert(Caps::OTP);
                unverified.insert(Caps::OTP);
            }
            let vendor = vendor_name(hid.vendor_id).to_string();
            let model = if is_token2 {
                keyroost_proto::token2_pid_label(hid.product_id)
                    .map(str::to_owned)
                    .unwrap_or_else(|| clean_model(&hid.product_name, &vendor))
            } else {
                clean_model(&hid.product_name, &vendor)
            };
            devices.push(Device {
                id,
                name: keyring.name_for(Some(&serial)).map(str::to_owned),
                vendor,
                model,
                serial,
                transport: "USB · FIDO HID".into(),
                firmware: String::new(),
                caps,
                unverified,
                kind: DeviceKind::Key,
                hid_path: Some(hid.path.clone()),
                reader: reader_name,
            });
        }
    }

    // Any id shared by >1 device would collapse them into one selectable
    // identity; disambiguate using the per-port reader/hid path (KEY-015).
    let mut id_counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for d in &devices {
        *id_counts.entry(d.id.clone()).or_default() += 1;
    }
    for d in devices.iter_mut() {
        if id_counts.get(&d.id).copied().unwrap_or(0) > 1 {
            let suffix = d
                .reader
                .clone()
                .or_else(|| d.hid_path.as_ref().map(|p| p.display().to_string()))
                .unwrap_or_default();
            d.id = format!("{}#{}", d.id, suffix);
        }
    }

    devices.sort_by(|a, b| {
        (a.kind == DeviceKind::Token)
            .cmp(&(b.kind == DeviceKind::Token))
            .then_with(|| a.model.cmp(&b.model))
            .then_with(|| a.id.cmp(&b.id))
    });
    devices
}

/// Build the unified device list. Blocking: enumerates FIDO HID nodes and probes
/// PC/SC readers, then correlates. A HID-layer failure is a hard error; PC/SC
/// problems degrade to an empty probe list (FIDO-only keys still appear).
pub fn enumerate() -> Result<Vec<Device>, String> {
    let hids = keyroost_hid::enumerate().map_err(|e| format!("HID enumeration failed: {e}"))?;
    let probes = keyroost_transport::probe_readers().unwrap_or_default();
    let keyring = Keyring::load_default().unwrap_or_default();
    Ok(correlate(&hids, &probes, &keyring))
}

/// One applet-reset step in a whole-device factory reset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResetStep {
    Oath,
    OpenPgp,
    Token2Otp,
    /// Resetting the PIV applet — `keyroost_transport::PivSession::
    /// factory_reset` decides on its own, from a live fingerprint, exactly
    /// which mechanism this ends up running: a PIV-only reset (several
    /// shapes, `keyroost_transport::FactoryResetPlan`), or a device-wide one
    /// (`keyroost_piv::compat::PivExtension::ResetGlobal` — today: HID
    /// Crescendo's RESET CARD against its ACA instance, taking at least one
    /// other applet down with PIV). Placed right before [`Self::Fido`],
    /// not with the other card applets above: unlike them, whether this step
    /// belongs in the plan *at all* needs that same live fingerprint —
    /// `factory_reset` refuses outright when neither mechanism is available —
    /// so a caller that has fingerprinted and found neither should remove it
    /// with [`exclude_unresettable_piv`] before running the plan, the same
    /// way [`Self::Fido`] always stays last regardless.
    Piv,
    Fido,
}

impl ResetStep {
    /// Short badge label — matches the capability vocabulary the CLI/GUI
    /// already show, so the reset summary reads consistently.
    pub fn label(self) -> &'static str {
        match self {
            ResetStep::Oath => "OATH",
            ResetStep::OpenPgp => "OpenPGP",
            ResetStep::Piv => "PIV",
            ResetStep::Token2Otp => "OTP",
            ResetStep::Fido => "FIDO2",
        }
    }
}

/// Ordered factory-reset steps for a key with these capabilities. Card
/// applets first (silent wipes), FIDO last (its reset needs a replug +
/// touch ceremony, so it ends the flow); [`ResetStep::Piv`] sits immediately
/// before FIDO rather than alongside the other card applets — see that
/// variant's doc for why. Only applets the key advertises appear. Pure — the
/// single source of truth both the CLI and GUI consume, so they can never
/// disagree about what "everything" means.
///
/// Callers pass [`Device::caps`], the *offered* set, so an unverified
/// capability (see [`CapState::Unverified`]) gets its reset step too:
/// unverified always behaves as "offer it", and the attempt itself reports
/// whether the applet is really there. [`ResetStep::Piv`] is the one
/// exception this doesn't itself resolve: `Caps::PIV` says the applet is
/// there, not that it can be reset at all — call
/// [`exclude_unresettable_piv`] once a live fingerprint confirms it can't.
pub fn factory_reset_plan(caps: Caps) -> Vec<ResetStep> {
    let mut steps = Vec::new();
    if caps.has(Caps::OATH) {
        steps.push(ResetStep::Oath);
    }
    if caps.has(Caps::PGP) {
        steps.push(ResetStep::OpenPgp);
    }
    if caps.has(Caps::OTP) {
        steps.push(ResetStep::Token2Otp);
    }
    if caps.has(Caps::PIV) {
        steps.push(ResetStep::Piv);
    }
    if caps.has(Caps::FIDO2) {
        steps.push(ResetStep::Fido);
    }
    steps
}

/// Remove [`ResetStep::Piv`] from an already-built [`factory_reset_plan`]
/// result — call once a live fingerprint
/// (`keyroost_transport::PivSession::preview_factory_reset` resolving
/// `keyroost_transport::PivResetPreview::Unsupported`) confirms neither
/// `keyroost_piv::compat::PivExtension::Reset` nor `PivExtension::
/// ResetGlobal` is available, so a factory reset never shows the applet in
/// its confirmation dialog, nor attempts it, for a device that was never
/// going to accept any reset mechanism.
///
/// Separate from `factory_reset_plan` itself on purpose: that function is
/// pure and caps-only, but whether PIV can be reset at all needs a live
/// fingerprint that only a caller holding an open session can have. A
/// no-op if the plan doesn't contain [`ResetStep::Piv`] to begin with (e.g.
/// `Caps::PIV` wasn't set).
pub fn exclude_unresettable_piv(plan: &mut Vec<ResetStep>) {
    plan.retain(|s| *s != ResetStep::Piv);
}

/// The step name to show for a [`StepOutcome::WipedGlobal`] report line,
/// naming the whole device rather than just [`ResetStep::Piv`] — see that
/// variant's doc for why. Shared between the CLI and GUI so the two never
/// drift on the wording.
pub const PIV_GLOBAL_RESET_LABEL: &str = "Whole device (via PIV)";

/// The outcome of one reset step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StepOutcome {
    /// The applet was reset to factory state.
    Wiped,
    /// Wiped, but via a device-wide reset mechanism that took at least one
    /// other applet down with it, not a mechanism confined to this one
    /// applet — so a report line naming only this step's applet (`PIV`)
    /// undersells what actually happened. Callers that only care whether the
    /// wipe itself happened should treat this the same as `Wiped`; callers
    /// building a *label* for the step should use [`PIV_GLOBAL_RESET_LABEL`]
    /// instead of [`ResetStep::label`]. Today's one producer: PIV's
    /// `PivExtension::ResetGlobal` path succeeding cleanly
    /// (`keyroost_transport::FactoryResetOutcome::WipedGlobal`).
    WipedGlobal,
    /// The applet *was* reset to factory state, but a non-fatal follow-up
    /// step afterward failed; the string describes what went wrong and what
    /// to do about it. The applet itself isn't left in its old state —
    /// unlike `Failed`, a caller that only cares whether the wipe itself
    /// happened (pane re-initialisation, a plain wiped/not-wiped count)
    /// should treat this the same as `Wiped` — but the follow-up failure is
    /// real and still needs surfacing on its own, the same way `Failed`
    /// does. Today's one producer: PIV's device-wide reset mechanism, when
    /// RESET CARD succeeds but restoring the courtesy XAUTH-key factory
    /// default afterward fails
    /// (`keyroost_transport::FactoryResetOutcome::WipedKeyRestoreFailed`).
    WipedWithWarning(String),
    /// The reset was attempted and failed; the string is the reason.
    Failed(String),
    /// The step was never attempted; the string says why. `factory_reset_plan`
    /// itself only *offers* a step when its applet is present (an absent
    /// applet is simply omitted, not reported `Skipped`) — this variant is for
    /// a step that *was* offered but the runner decided, once it had live
    /// device data a `Caps`-only plan can't see, not to touch it. Today's one
    /// producer: the PIV step, when `keyroost_transport::PivSession::
    /// factory_reset` refuses before attempting anything —
    /// `keyroost_piv::compat::PivExtension::Reset` and `ResetGlobal` both
    /// known-unsupported (`exclude_unresettable_piv` should normally have
    /// dropped the step already; this is the fallback for when the earlier
    /// fingerprint that decision relied on couldn't be taken and the plan
    /// still offered it), or `PivQuirk::ResetNeedsManagementAuth` applying
    /// with no credential supplied — either way, better to say so plainly
    /// than to either silently omit the applet or burn its PIN/PUK for a
    /// RESET that was never going to be accepted.
    Skipped(String),
}

/// One line of a factory-reset report: which applet, and how it went.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepReport {
    pub step: ResetStep,
    pub outcome: StepOutcome,
}

#[cfg(test)]
mod tests {
    use super::*;
    use keyroost_hid::{HID_USAGE_FIDO_AUTHENTICATOR, HID_USAGE_PAGE_FIDO};

    fn hid(
        vid: u16,
        pid: u16,
        path: &str,
        serial: Option<&str>,
        bus: Option<u8>,
        addr: Option<u8>,
    ) -> HidDevice {
        HidDevice {
            path: path.into(),
            vendor_id: vid,
            product_id: pid,
            product_name: "Security Key".into(),
            usage_page: HID_USAGE_PAGE_FIDO,
            usage: HID_USAGE_FIDO_AUTHENTICATOR,
            serial_number: serial.map(str::to_owned),
            usb_bus: bus,
            usb_address: addr,
        }
    }

    // A test fixture mirroring ReaderProbe's fields; the arg count is inherent.
    #[allow(clippy::too_many_arguments)]
    fn probe(
        name: &str,
        molto2: bool,
        oath: bool,
        pgp: bool,
        piv: bool,
        yk_serial: Option<&str>,
        bus: Option<u8>,
        addr: Option<u8>,
    ) -> ReaderProbe {
        ReaderProbe {
            reader_name: name.into(),
            is_molto2: molto2,
            serial: None,
            openpgp_manufacturer: None,
            has_oath: oath,
            has_openpgp: pgp,
            has_piv: piv,
            has_fido: false,
            has_otp: false,
            is_prog: false,
            prog_serial: None,
            yubikey_serial: yk_serial.map(str::to_owned),
            usb_bus: bus,
            usb_address: addr,
        }
    }

    #[test]
    fn molto2_with_no_hid_sibling_is_a_token() {
        let probes = [probe(
            "TOKEN2 Molto2 (5C7D…) 02 00",
            true,
            false,
            false,
            false,
            None,
            Some(9),
            Some(4),
        )];
        let devs = correlate(&[], &probes, &Keyring::default());
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0].kind, DeviceKind::Token);
        assert_eq!(devs[0].model, "Molto2");
        assert!(devs[0].caps.has(Caps::TOTP));
    }

    #[test]
    fn molto2_flag_with_hid_sibling_is_not_a_token() {
        let probes = [probe(
            "TOKEN2 something 02 00",
            true,
            false,
            false,
            false,
            None,
            Some(9),
            Some(4),
        )];
        let hids = [hid(
            keyroost_proto::USB_VID,
            0x0013,
            "/dev/hidraw9",
            Some("S1"),
            Some(9),
            Some(4),
        )];
        let devs = correlate(&hids, &probes, &Keyring::default());
        assert!(devs.iter().all(|d| d.kind != DeviceKind::Token));
    }

    #[test]
    fn duplicate_serial_fido_keys_stay_distinct() {
        // Two pure-FIDO keys that advertise the SAME USB serial must not collapse
        // into one selectable identity (KEY-015).
        let hids = [
            hid(
                0x1234,
                0x0001,
                "/dev/hidraw0",
                Some("CLONE"),
                Some(1),
                Some(2),
            ),
            hid(
                0x1234,
                0x0001,
                "/dev/hidraw1",
                Some("CLONE"),
                Some(1),
                Some(3),
            ),
        ];
        let devs = correlate(&hids, &[], &Keyring::default());
        assert_eq!(devs.len(), 2, "duplicate serials must not merge");
        assert_ne!(devs[0].id, devs[1].id, "ids must be distinct");
    }

    #[test]
    fn two_token2_keys_are_deduped_by_topology() {
        // #51: two Token2 PIN+ keys, each with a FIDO HID node AND a PC/SC reader
        // whose name contains "Token2". The vendor-name heuristic matches both
        // readers and gives up, so without topology disambiguation each key was
        // listed twice (its CCID device plus an unmerged HID-only device).
        let probes = [
            probe(
                "Token2 PIN+ Bio 00 00",
                false,
                true,
                false,
                false,
                None,
                Some(1),
                Some(2),
            ),
            probe(
                "Token2 PIN+ Octo 00 00",
                false,
                true,
                false,
                false,
                None,
                Some(1),
                Some(3),
            ),
        ];
        let hids = [
            hid(
                keyroost_proto::USB_VID,
                0x0031,
                "/dev/hidraw1",
                None,
                Some(1),
                Some(2),
            ),
            hid(
                keyroost_proto::USB_VID,
                0x0032,
                "/dev/hidraw2",
                None,
                Some(1),
                Some(3),
            ),
        ];
        let devs = correlate(&hids, &probes, &Keyring::default());
        assert_eq!(
            devs.len(),
            2,
            "each key should appear once, got {} devices",
            devs.len()
        );
        assert!(devs.iter().all(|d| d.kind == DeviceKind::Key));
        assert!(
            devs.iter().all(|d| d.transport.contains("FIDO HID")),
            "both keys should have merged their FIDO HID into the CCID device"
        );
    }

    #[test]
    fn yubikey_unions_hid_fido_with_ccid_applets() {
        let probes = [probe(
            "Yubico YubiKey OTP+FIDO+CCID 00 00",
            false,
            true,
            true,
            true,
            Some("37806840"),
            Some(9),
            Some(16),
        )];
        let hids = [hid(
            0x1050,
            0x0407,
            "/dev/hidraw17",
            None,
            Some(9),
            Some(16),
        )];
        let devs = correlate(&hids, &probes, &Keyring::default());
        assert_eq!(devs.len(), 1);
        let d = &devs[0];
        assert_eq!(d.kind, DeviceKind::Key);
        assert!(
            d.caps.has(Caps::FIDO2)
                && d.caps.has(Caps::OATH)
                && d.caps.has(Caps::PGP)
                && d.caps.has(Caps::PIV)
        );
        assert_eq!(d.serial, "37806840");
    }

    #[test]
    fn solo2_merges_by_shared_serial() {
        let serial = "07A9568FBE31AD5DAD1F2298476CF0D4";
        let probes = [probe(
            "SoloKeys Solo 2 [CCID/ICCD Interface] 01 00",
            false,
            true,
            false,
            false,
            None,
            Some(9),
            Some(15),
        )];
        let hids = [hid(
            0x1209,
            0xbeee,
            "/dev/hidraw14",
            Some(serial),
            Some(9),
            Some(15),
        )];
        let devs = correlate(&hids, &probes, &Keyring::default());
        assert!(devs
            .iter()
            .any(|d| d.kind == DeviceKind::Key && d.caps.has(Caps::FIDO2)));
        assert!(devs.iter().all(|d| d.kind != DeviceKind::Token));
    }

    #[test]
    fn token2_fido_key_gets_otp_cap_by_pid() {
        let probes: [ReaderProbe; 0] = [];
        let hids = [hid(
            keyroost_proto::USB_VID,
            0x0013,
            "/dev/hidraw9",
            Some("S1"),
            Some(9),
            Some(4),
        )];
        let devs = correlate(&hids, &probes, &Keyring::default());
        assert_eq!(devs.len(), 1);
        assert!(devs[0].caps.has(Caps::FIDO2) && devs[0].caps.has(Caps::OTP));
    }

    #[test]
    fn a_pid_function_set_never_hides_the_otp_surface() {
        // v0.7.7 suppressed OTP for product ids whose vendor function set omits
        // it (#82). Token2 corrected the premise in #95: Bio3 (0x0204) HAS OTP,
        // over CCID, despite reading FIDO+PGP — it has no HOTP-over-HID and so
        // ships with the HID channel disabled. A function set that omits OTP
        // therefore does not mean the applet is absent, only that it may live
        // on a channel this enumeration cannot see.
        //
        // 0x0204 is the vendor-confirmed case; the rest share the same shape
        // and the same unverified premise, so none may be denied the surface.
        for pid in [0x0024u16, 0x0025, 0x0014, 0x0015, 0x0200, 0x0204, 0x0205] {
            let hids = [hid(
                keyroost_proto::USB_VID,
                pid,
                "/dev/hidraw9",
                Some("S1"),
                Some(9),
                Some(4),
            )];
            let devs = correlate(&hids, &[], &Keyring::default());
            assert_eq!(devs.len(), 1);
            assert!(
                devs[0].caps.has(Caps::OTP),
                "PID {pid:#06x} must keep the OTP surface: hiding an applet a key \
                 really has (Bio3, #95) is worse than offering one that turns out \
                 to be absent, which now fails with an actionable message"
            );
        }
    }

    #[test]
    fn the_otp_surface_survives_a_merge_into_a_card_row() {
        // The OTP bit is set in two places and both must agree — this is the
        // path where the HID node merges into an existing card row rather than
        // creating one.
        let probes = [probe(
            "Token2 PIN+ 00 00",
            false,
            false,
            true,
            false,
            None,
            Some(1),
            Some(2),
        )];
        let hids = [hid(
            keyroost_proto::USB_VID,
            0x0025,
            "/dev/hidraw1",
            Some("S2"),
            Some(1),
            Some(2),
        )];
        let devs = correlate(&hids, &probes, &Keyring::default());
        assert_eq!(devs.len(), 1);
        assert!(devs[0].caps.has(Caps::FIDO2) && devs[0].caps.has(Caps::PGP));
        assert!(devs[0].caps.has(Caps::OTP));
    }

    #[test]
    fn unknown_token2_pid_still_gets_otp_cap() {
        // FAIL OPEN. Token2 keeps adding product ids for new configurations; an
        // id we have not captured must keep the pre-table behaviour and still be
        // offered OTP. Hiding an applet a user's key really has is a worse
        // failure than showing a surface that turns out to be absent. Since #95
        // no id suppresses the capability at all — this pins the unknown-id half
        // of that rule specifically, so it survives any future re-narrowing.
        for pid in [0x0099u16, 0x0031, 0x0500] {
            assert_eq!(keyroost_proto::token2_functions(pid), None);
            let hids = [hid(
                keyroost_proto::USB_VID,
                pid,
                "/dev/hidraw9",
                Some("S1"),
                Some(9),
                Some(4),
            )];
            let devs = correlate(&hids, &[], &Keyring::default());
            assert_eq!(devs.len(), 1);
            assert!(
                devs[0].caps.has(Caps::OTP),
                "unknown PID {pid:#06x} must keep OTP"
            );
        }
    }

    #[test]
    fn probed_applets_are_present_not_unverified() {
        // Every capability on a probe-backed row came from a real SELECT over
        // the reader — ground truth, so the tri-state reads Present.
        let probes = [probe(
            "Yubico YubiKey OTP+FIDO+CCID 00 00",
            false,
            true,
            true,
            true,
            Some("37806840"),
            Some(9),
            Some(16),
        )];
        let hids = [hid(
            0x1050,
            0x0407,
            "/dev/hidraw17",
            None,
            Some(9),
            Some(16),
        )];
        let d = &correlate(&hids, &probes, &Keyring::default())[0];
        for c in [Caps::FIDO2, Caps::OATH, Caps::PGP, Caps::PIV] {
            assert_eq!(d.cap_state(c), CapState::Present);
        }
        assert!(d.unverified.is_empty());
    }

    #[test]
    fn probed_absent_stays_absent() {
        // A SELECT the card declined is recorded absence, not an offer: the
        // surface is neither offered nor rendered. (OATH answered; PGP/PIV
        // declined.)
        let probes = [probe(
            "Yubico YubiKey OTP+FIDO+CCID 00 00",
            false,
            true,
            false,
            false,
            Some("37806840"),
            Some(9),
            Some(16),
        )];
        let d = &correlate(&[], &probes, &Keyring::default())[0];
        assert_eq!(d.cap_state(Caps::OATH), CapState::Present);
        assert_eq!(d.cap_state(Caps::PGP), CapState::Absent);
        assert_eq!(d.cap_state(Caps::PIV), CapState::Absent);
        assert!(!d.caps.has(Caps::PGP) && !d.caps.has(Caps::PIV));
    }

    #[test]
    fn hid_only_token2_otp_is_unverified_and_still_offered() {
        // A USB-HID-only enumeration has asked the device nothing over a card
        // channel. FIDO2 is Present (the HID node is the evidence); OTP is
        // offered on the vendor hint — and now honestly recorded as
        // Unverified rather than silently written down as present.
        let hids = [hid(
            keyroost_proto::USB_VID,
            0x0013,
            "/dev/hidraw9",
            Some("S1"),
            Some(9),
            Some(4),
        )];
        let d = &correlate(&hids, &[], &Keyring::default())[0];
        assert_eq!(d.cap_state(Caps::FIDO2), CapState::Present);
        assert_eq!(d.cap_state(Caps::OTP), CapState::Unverified);
        // Unverified ALWAYS behaves as "offer it": the caps bit is set, so
        // every existing caller (targeting, tabs, reset planning) sees it.
        assert!(d.caps.has(Caps::OTP));
        assert_eq!(
            factory_reset_plan(d.caps),
            vec![ResetStep::Token2Otp, ResetStep::Fido],
            "an unverified OTP capability must still get its reset step"
        );
        assert_eq!(
            d.cap_badge_states(),
            vec![("FIDO2", CapState::Present), ("OTP", CapState::Unverified)]
        );
    }

    #[test]
    fn probe_answer_beats_the_vendor_hint_on_merge() {
        // When the reader DID answer the OTP applet's SELECT, the merge keeps
        // it verified — the hint never downgrades ground truth.
        let mut p = probe(
            "Token2 PIN+ 00 00",
            false,
            false,
            false,
            false,
            None,
            Some(1),
            Some(2),
        );
        p.has_otp = true;
        let hids = [hid(
            keyroost_proto::USB_VID,
            0x0025,
            "/dev/hidraw1",
            Some("S2"),
            Some(1),
            Some(2),
        )];
        let devs = correlate(&hids, std::slice::from_ref(&p), &Keyring::default());
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0].cap_state(Caps::OTP), CapState::Present);
        assert!(!devs[0].unverified.has(Caps::OTP));
    }

    #[test]
    fn merged_card_row_offers_otp_as_unverified_when_the_probe_declined() {
        // The probe SELECTed the OTP applet and got a decline, but the vendor
        // hint still offers the surface (#95: the applet may live on a channel
        // the probe cannot see). Offered — and labelled unverified, because
        // neither answer was proven.
        let probes = [probe(
            "Token2 PIN+ 00 00",
            false,
            false,
            true,
            false,
            None,
            Some(1),
            Some(2),
        )];
        let hids = [hid(
            keyroost_proto::USB_VID,
            0x0025,
            "/dev/hidraw1",
            Some("S2"),
            Some(1),
            Some(2),
        )];
        let devs = correlate(&hids, &probes, &Keyring::default());
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0].cap_state(Caps::PGP), CapState::Present);
        assert_eq!(devs[0].cap_state(Caps::OTP), CapState::Unverified);
        assert!(devs[0].caps.has(Caps::OTP), "still offered");
        assert_eq!(devs[0].cap_state(Caps::FIDO2), CapState::Present);
    }

    #[test]
    fn unverified_never_comes_from_the_pid_table() {
        // Standing decision: no device→capability matrix. The tri-state must
        // be identical across product ids — one whose vendor function set
        // lists OTP, one whose set omits it (Bio3, the #95 case), and ids the
        // table has never heard of. Only the vendor id (a label-grade hint)
        // and real probes may feed the state.
        let mut states = std::collections::HashSet::new();
        for pid in [0x0013u16, 0x0204, 0x0099, 0x0500] {
            let hids = [hid(
                keyroost_proto::USB_VID,
                pid,
                "/dev/hidraw9",
                Some("S1"),
                Some(9),
                Some(4),
            )];
            let d = &correlate(&hids, &[], &Keyring::default())[0];
            states.insert(format!("{:?}", d.cap_state(Caps::OTP)));
        }
        assert_eq!(
            states.into_iter().collect::<Vec<_>>(),
            vec!["Unverified".to_string()],
            "every Token2 product id must get the same OTP state"
        );
        // Another vendor's key is untouched by the hint: Absent, not offered.
        let other = [hid(0x1209, 0x0013, "/dev/hidraw3", Some("SK"), None, None)];
        let d = &correlate(&other, &[], &Keyring::default())[0];
        assert_eq!(d.cap_state(Caps::OTP), CapState::Absent);
    }

    #[test]
    fn unverified_is_always_a_subset_of_caps() {
        // The structural guarantee behind "unverified still behaves as offer
        // it": an unverified bit outside `caps` would be a capability that is
        // rendered but not offered, which no surface handles.
        let probes = [probe(
            "Token2 PIN+ 00 00",
            false,
            true,
            false,
            false,
            None,
            Some(1),
            Some(2),
        )];
        let hids = [
            hid(
                keyroost_proto::USB_VID,
                0x0025,
                "/dev/hidraw1",
                Some("S2"),
                Some(1),
                Some(2),
            ),
            hid(0x1050, 0x0407, "/dev/hidraw2", Some("YK"), Some(1), Some(3)),
        ];
        for d in correlate(&hids, &probes, &Keyring::default()) {
            for c in [
                Caps::FIDO2,
                Caps::OATH,
                Caps::PGP,
                Caps::PIV,
                Caps::TOTP,
                Caps::OTP,
                Caps::PROG,
            ] {
                assert!(
                    !d.unverified.has(c) || d.caps.has(c),
                    "unverified must be a subset of caps"
                );
            }
        }
    }

    #[test]
    fn otp_suppression_is_scoped_to_the_token2_vid() {
        // The PID table is Token2's; another vendor's key that happens to use a
        // colliding product id is untouched by it — no OTP either way, since OTP
        // is a Token2-only applet here.
        for pid in [0x0025u16, 0x0026] {
            let hids = [hid(
                0x1209,
                pid,
                "/dev/hidraw3",
                Some("SK"),
                Some(9),
                Some(7),
            )];
            let devs = correlate(&hids, &[], &Keyring::default());
            assert_eq!(devs.len(), 1);
            assert_eq!(devs[0].vendor, "SoloKeys");
            assert!(devs[0].caps.has(Caps::FIDO2));
            assert!(!devs[0].caps.has(Caps::OTP));
        }
    }

    #[test]
    fn caps_insert_has_and_empty() {
        let mut c = Caps::default();
        assert!(c.is_empty());
        c.insert(Caps::FIDO2);
        c.insert(Caps::PIV);
        assert!(c.has(Caps::FIDO2));
        assert!(c.has(Caps::PIV));
        assert!(!c.has(Caps::OATH));
        assert!(!c.is_empty());
    }

    #[test]
    fn clean_model_strips_vendor_brackets_and_index() {
        assert_eq!(
            clean_model(
                "SoloKeys Solo 2 [CCID/ICCD Interface] (07A9) 01 00",
                "SoloKeys"
            ),
            "Solo 2"
        );
        assert_eq!(
            clean_model("Yubico YubiKey OTP+FIDO+CCID 00 00", "Yubico"),
            "YubiKey"
        );
        assert_eq!(clean_model("Nitrokey 3", "Nitrokey"), "3");
    }

    #[test]
    fn vendor_name_maps_known_vids() {
        assert_eq!(vendor_name(0x1050), "Yubico");
        assert_eq!(vendor_name(0x1209), "SoloKeys");
        assert_eq!(vendor_name(0x349e), "Token2");
        assert_eq!(vendor_name(0xffff), "Security key");
    }

    #[test]
    fn card_vendor_prefers_openpgp_manufacturer_over_reader_name() {
        // Known manufacturer id -> registry vendor name, regardless of reader.
        assert_eq!(
            card_vendor(Some(0x0011), "Alcor Micro Corp. AU9540 00 00"),
            "Token2"
        );
        assert_eq!(
            card_vendor(Some(0x000F), "SCM Microsystems Inc. reader 00"),
            "Nitrokey"
        );
        // No/unknown manufacturer id -> fall back to the reader-name first word.
        assert_eq!(card_vendor(None, "Feitian ePass 00"), "Feitian");
        assert_eq!(card_vendor(Some(0x1234), "SCM Micro 00"), "SCM");
        // Empty reader name with no manufacturer -> the existing "Key" default.
        assert_eq!(card_vendor(None, ""), "Key");
    }

    #[test]
    fn two_yubikeys_do_not_collapse() {
        // Two YubiKeys, disambiguated by USB topology — must stay two devices, each
        // with its own serial and FIDO2+OATH caps (guards the phase-3 topology match).
        let probes = [
            probe(
                "Yubico YubiKey OTP+FIDO+CCID 00 00",
                false,
                true,
                false,
                false,
                Some("111"),
                Some(9),
                Some(16),
            ),
            probe(
                "Yubico YubiKey OTP+FIDO+CCID 01 00",
                false,
                true,
                false,
                false,
                Some("222"),
                Some(9),
                Some(17),
            ),
        ];
        let hids = [
            hid(0x1050, 0x0407, "/dev/hidraw17", None, Some(9), Some(16)),
            hid(0x1050, 0x0407, "/dev/hidraw18", None, Some(9), Some(17)),
        ];
        let devs = correlate(&hids, &probes, &Keyring::default());
        assert_eq!(devs.len(), 2);
        let serials: std::collections::HashSet<String> =
            devs.iter().map(|d| d.serial.clone()).collect();
        assert!(serials.contains("111") && serials.contains("222"));
        assert!(devs
            .iter()
            .all(|d| d.caps.has(Caps::FIDO2) && d.caps.has(Caps::OATH)));
    }

    #[test]
    fn cap_badges_vocabulary() {
        // A Token shows a single "TOTP token" badge regardless of other bits.
        let probes = [probe(
            "TOKEN2 Molto2 02 00",
            true,
            false,
            false,
            false,
            None,
            Some(9),
            Some(4),
        )];
        let molto = &correlate(&[], &probes, &Keyring::default())[0];
        assert_eq!(molto.cap_badges(), vec!["TOTP token"]);

        // A Token2 FIDO key (FIDO2 + OTP by PID) badges both, in canonical order.
        let hids = [hid(
            keyroost_proto::USB_VID,
            0x0013,
            "/dev/hidraw9",
            Some("S1"),
            Some(9),
            Some(4),
        )];
        let key = &correlate(&hids, &[], &Keyring::default())[0];
        assert_eq!(key.cap_badges(), vec!["FIDO2", "OTP"]);

        // A full YubiKey badges FIDO2/OATH/PGP/PIV in order (no OTP).
        let yk_probe = [probe(
            "Yubico YubiKey OTP+FIDO+CCID 00 00",
            false,
            true,
            true,
            true,
            Some("37806840"),
            Some(9),
            Some(16),
        )];
        let yk_hid = [hid(
            0x1050,
            0x0407,
            "/dev/hidraw17",
            None,
            Some(9),
            Some(16),
        )];
        let yk = &correlate(&yk_hid, &yk_probe, &Keyring::default())[0];
        assert_eq!(yk.cap_badges(), vec!["FIDO2", "OATH", "PGP", "PIV"]);
    }

    #[test]
    fn fido_only_non_token2_key_is_plain_fido2() {
        // A Nitrokey FIDO HID with no CCID reader → one Key, FIDO2 only (no OTP),
        // vendor/model derived from the USB vendor id + product name.
        let probes: [ReaderProbe; 0] = [];
        let mut h = hid(
            0x20a0,
            0x0001,
            "/dev/hidraw3",
            Some("NK1"),
            Some(9),
            Some(20),
        );
        h.product_name = "Nitrokey 3".into();
        let devs = correlate(&[h], &probes, &Keyring::default());
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0].kind, DeviceKind::Key);
        assert!(devs[0].caps.has(Caps::FIDO2));
        assert!(!devs[0].caps.has(Caps::OTP));
        assert_eq!(devs[0].vendor, "Nitrokey");
    }

    #[test]
    fn yubikey_with_reader_and_fido_only_yubico_key_stay_distinct() {
        // A full YubiKey (reader + HID) next to a FIDO-only Security Key by
        // Yubico. The second node reports its own bus/address and matches no
        // reader — it must NOT adopt the YubiKey's reader "because there is only
        // one". Merging them put the Security Key's hid_path on the YubiKey's
        // row, so every FIDO operation (PIN entry, creds-list, creds-delete)
        // landed on a key the user never selected.
        let probes = [probe(
            "Yubico YubiKey OTP+FIDO+CCID 00 00",
            false,
            true,
            false,
            false,
            Some("11111111"),
            Some(9),
            Some(16),
        )];
        let hids = [
            hid(0x1050, 0x0407, "/dev/hidraw17", None, Some(9), Some(16)),
            hid(0x1050, 0x0406, "/dev/hidraw18", None, Some(9), Some(20)),
        ];
        let devs = correlate(&hids, &probes, &Keyring::default());
        assert_eq!(devs.len(), 2, "two physical keys must stay two devices");
        let card = devs
            .iter()
            .find(|d| d.reader.is_some())
            .expect("the YubiKey keeps its reader");
        assert_eq!(card.serial, "11111111");
        assert_eq!(
            card.hid_path.as_deref(),
            Some(std::path::Path::new("/dev/hidraw17")),
            "the reader-backed row must carry its OWN FIDO node"
        );
        let fido_only = devs
            .iter()
            .find(|d| d.reader.is_none())
            .expect("the FIDO-only key stands alone");
        assert_eq!(
            fido_only.hid_path.as_deref(),
            Some(std::path::Path::new("/dev/hidraw18"))
        );
        assert!(
            fido_only.serial.is_empty(),
            "the FIDO-only key must not inherit the other key's CCID serial"
        );
    }

    #[test]
    fn fido_only_yubico_key_never_adopts_an_unrelated_reader() {
        // A FIDO-only Yubico key plus one unrelated reader holding a PIV card.
        // Collapsing them hid the card behind the key's row and bypassed the
        // CLI's "several keys are connected, select one" refusal, so a
        // factory-reset ran against a card the user never selected.
        let unrelated = probe(
            "Alcor Micro AU9540 00 00",
            false,
            false,
            false,
            true,
            None,
            Some(9),
            Some(30),
        );
        // Topology reported and unmatched.
        let devs = correlate(
            &[hid(
                0x1050,
                0x0406,
                "/dev/hidraw18",
                None,
                Some(9),
                Some(20),
            )],
            std::slice::from_ref(&unrelated),
            &Keyring::default(),
        );
        assert_eq!(devs.len(), 2, "an unrelated reader is not this key's");
        // Same again with no topology at all (the Windows/macOS HID backend):
        // the vendor plausibility check alone must still keep them apart.
        let devs = correlate(
            &[hid(0x1050, 0x0406, "/dev/hidraw18", None, None, None)],
            std::slice::from_ref(&unrelated),
            &Keyring::default(),
        );
        assert_eq!(
            devs.len(),
            2,
            "a non-Yubico reader is never a Yubico key's fallback candidate"
        );
    }

    #[test]
    fn yubikey_without_reported_topology_still_merges() {
        // hidapi on Windows and macOS reports no bus/address at all, so the
        // single-candidate fallback is the ONLY correlation signal there. One
        // key, one Yubico reader: they must still merge into one device.
        let probes = [probe(
            "Yubico YubiKey OTP+FIDO+CCID 00 00",
            false,
            true,
            false,
            false,
            Some("11111111"),
            None,
            None,
        )];
        let hids = [hid(0x1050, 0x0407, "/dev/hidraw17", None, None, None)];
        let devs = correlate(&hids, &probes, &Keyring::default());
        assert_eq!(
            devs.len(),
            1,
            "correlation must still work without topology"
        );
        assert_eq!(devs[0].serial, "11111111");
        assert!(devs[0].caps.has(Caps::FIDO2) && devs[0].caps.has(Caps::OATH));
        assert!(devs[0].transport.contains("FIDO HID"));
    }

    /// The reproduction shape for the reader-theft regression: one key that has
    /// both a reader and a FIDO node (bus 2 / address 7), and a second key of the
    /// *same vendor* that is FIDO-only (bus 2 / address 5). The reader's name
    /// carries the vendor word, so the FIDO-only node matches it by name — but it
    /// reported topology and matched no reader, which is positive evidence it is a
    /// different device. Returned as `(reader-backed row, FIDO-only row)`.
    fn nitrokey_pair(fido_only_first: bool) -> (Device, Device) {
        let probes = [probe(
            "Nitrokey 3 [CCID/ICCD Interface] 00 00",
            false,
            true,
            false,
            false,
            None,
            Some(2),
            Some(7),
        )];
        let mut sibling = hid(0x20a0, 0x42b2, "/dev/hidraw4", None, Some(2), Some(7));
        sibling.product_name = "Nitrokey 3".into();
        let mut fido_only = hid(0x20a0, 0x42b2, "/dev/hidraw3", None, Some(2), Some(5));
        fido_only.product_name = "Nitrokey 3".into();
        let hids = if fido_only_first {
            [fido_only, sibling]
        } else {
            [sibling, fido_only]
        };
        let devs = correlate(&hids, &probes, &Keyring::default());
        assert_eq!(devs.len(), 2, "two physical keys must stay two devices");
        let card = devs
            .iter()
            .find(|d| d.reader.is_some())
            .expect("the CCID key keeps its reader")
            .clone();
        let alone = devs
            .iter()
            .find(|d| d.reader.is_none())
            .expect("the FIDO-only key stands alone")
            .clone();
        (card, alone)
    }

    #[test]
    fn exact_topology_wins_the_reader_in_either_enumeration_order() {
        // A weak name-only guess must never claim a reader ahead of the node that
        // proves, by exact USB bus+address, that it is that reader's own sibling.
        // Binding first-come-first-served made the answer depend on enumeration
        // order: card operations went to one physical key and FIDO operations to
        // another, silently, under a single row.
        for fido_only_first in [true, false] {
            let (card, alone) = nitrokey_pair(fido_only_first);
            assert_eq!(
                card.hid_path.as_deref(),
                Some(std::path::Path::new("/dev/hidraw4")),
                "the reader-backed row must carry its OWN FIDO node \
                 (fido_only_first = {fido_only_first})"
            );
            assert_eq!(
                alone.hid_path.as_deref(),
                Some(std::path::Path::new("/dev/hidraw3")),
                "the FIDO-only key keeps its own node (fido_only_first = {fido_only_first})"
            );
            assert!(card.caps.has(Caps::OATH) && card.caps.has(Caps::FIDO2));
            assert!(!alone.caps.has(Caps::OATH));
        }
    }

    #[test]
    fn token2_fido_only_key_never_steals_a_sibling_readers_row() {
        // Same shape with Token2 keys, whose reader names also carry the vendor
        // word — and where a mixed row would send the OTP applet to one key and
        // the FIDO reset to another.
        for fido_only_first in [true, false] {
            let probes = [probe(
                "Token2 PIN+ Bio 00 00",
                false,
                true,
                false,
                false,
                None,
                Some(1),
                Some(2),
            )];
            let sibling = hid(
                keyroost_proto::USB_VID,
                0x0031,
                "/dev/hidraw1",
                None,
                Some(1),
                Some(2),
            );
            let fido_only = hid(
                keyroost_proto::USB_VID,
                0x0013,
                "/dev/hidraw2",
                None,
                Some(1),
                Some(5),
            );
            let hids = if fido_only_first {
                [fido_only, sibling]
            } else {
                [sibling, fido_only]
            };
            let devs = correlate(&hids, &probes, &Keyring::default());
            assert_eq!(devs.len(), 2, "two physical keys must stay two devices");
            let card = devs
                .iter()
                .find(|d| d.reader.is_some())
                .expect("reader row");
            assert_eq!(
                card.hid_path.as_deref(),
                Some(std::path::Path::new("/dev/hidraw1")),
                "the reader-backed row must carry its OWN FIDO node \
                 (fido_only_first = {fido_only_first})"
            );
            let alone = devs
                .iter()
                .find(|d| d.reader.is_none())
                .expect("FIDO-only row");
            assert_eq!(
                alone.hid_path.as_deref(),
                Some(std::path::Path::new("/dev/hidraw2"))
            );
        }
    }

    #[test]
    fn non_yubico_key_without_reported_topology_still_merges() {
        // The Windows/macOS HID backend reports no bus/address, so the vendor-name
        // fallback is the only correlation signal there. One key, one reader whose
        // name carries the vendor word: they must still merge into one device.
        let probes = [probe(
            "Nitrokey 3 [CCID/ICCD Interface] 00 00",
            false,
            true,
            false,
            false,
            None,
            None,
            None,
        )];
        let mut h = hid(0x20a0, 0x42b2, "/dev/hidraw3", None, None, None);
        h.product_name = "Nitrokey 3".into();
        let devs = correlate(&[h], &probes, &Keyring::default());
        assert_eq!(
            devs.len(),
            1,
            "correlation must still work without topology"
        );
        assert_eq!(
            devs[0].hid_path.as_deref(),
            Some(std::path::Path::new("/dev/hidraw3"))
        );
        assert!(devs[0].caps.has(Caps::FIDO2) && devs[0].caps.has(Caps::OATH));
        assert!(devs[0].transport.contains("FIDO HID"));
    }

    /// Two topology-free Yubico nodes and a single Yubico reader — the shape
    /// hidapi reports on Windows and macOS, where `usb_bus` is always `None`, so
    /// the vendor guess is the only correlation path. One of these nodes is a
    /// FIDO-only key with no card interface at all, but nothing in the reported
    /// data says which. Returned in the given enumeration order.
    fn topology_free_yubico_pair(fido_only_first: bool) -> Vec<Device> {
        let probes = [probe(
            "Yubico YubiKey OTP+FIDO+CCID 00 00",
            false,
            true,
            false,
            false,
            Some("11111111"),
            None,
            None,
        )];
        let card_sibling = hid(0x1050, 0x0407, "/dev/hidraw17", None, None, None);
        let fido_only = hid(0x1050, 0x0406, "/dev/hidraw18", None, None, None);
        let hids = if fido_only_first {
            [fido_only, card_sibling]
        } else {
            [card_sibling, fido_only]
        };
        correlate(&hids, &probes, &Keyring::default())
    }

    #[test]
    fn two_topology_free_nodes_contending_for_one_reader_bind_none() {
        // Neither node can be shown to own the reader, and guessing sends every
        // FIDO operation on that row — PIN change, credential deletion,
        // authenticatorReset — to whichever key the backend enumerated first.
        // The reader therefore stays on its own row, the same shape produced
        // when a key's reader is absent. Asserted in BOTH orders: the previous
        // test only checked that the reader was claimed once and that two hidraw
        // paths existed, which is true of the wrong binding too.
        for fido_only_first in [true, false] {
            let devs = topology_free_yubico_pair(fido_only_first);
            assert_eq!(
                devs.len(),
                3,
                "the card and both FIDO nodes each get their own row \
                 (fido_only_first = {fido_only_first})"
            );
            let claimed: Vec<&Device> = devs.iter().filter(|d| d.reader.is_some()).collect();
            assert_eq!(
                claimed.len(),
                1,
                "one reader, one row (fido_only_first = {fido_only_first})"
            );
            assert_eq!(
                claimed[0].hid_path, None,
                "an unresolvable tie must bind no FIDO node to the reader \
                 (fido_only_first = {fido_only_first})"
            );
            let mut paths: Vec<String> = devs
                .iter()
                .filter_map(|d| d.hid_path.as_ref().map(|p| p.display().to_string()))
                .collect();
            paths.sort();
            assert_eq!(
                paths,
                ["/dev/hidraw17", "/dev/hidraw18"],
                "each FIDO node keeps its own hidraw node (fido_only_first = {fido_only_first})"
            );
        }
    }

    #[test]
    fn contended_reader_serial_is_never_stamped_on_a_fido_row() {
        // The reader's CCID serial identifies exactly one physical key. Handing
        // it to both FIDO rows would make them indistinguishable — and would
        // defeat the re-check that a reset ran against the key the user picked.
        for fido_only_first in [true, false] {
            let devs = topology_free_yubico_pair(fido_only_first);
            let holders = devs.iter().filter(|d| d.serial == "11111111").count();
            assert_eq!(
                holders, 1,
                "only the card row may report the CCID serial \
                 (fido_only_first = {fido_only_first})"
            );
            for d in devs.iter().filter(|d| d.hid_path.is_some()) {
                assert!(
                    d.serial.is_empty(),
                    "a FIDO row must not inherit the card's serial \
                     (fido_only_first = {fido_only_first})"
                );
            }
        }
    }

    #[test]
    fn single_topology_free_node_still_merges_with_its_reader() {
        // The common Windows/macOS case, and the one the contention rule must
        // not cost us: one key, one reader, nothing to contend with — they merge
        // into a single row carrying both the reader and the FIDO node.
        let probes = [probe(
            "Yubico YubiKey OTP+FIDO+CCID 00 00",
            false,
            true,
            false,
            false,
            Some("11111111"),
            None,
            None,
        )];
        let hids = [hid(0x1050, 0x0407, "/dev/hidraw17", None, None, None)];
        let devs = correlate(&hids, &probes, &Keyring::default());
        assert_eq!(devs.len(), 1, "one key must still be one row");
        assert_eq!(devs[0].serial, "11111111");
        assert_eq!(
            devs[0].hid_path.as_deref(),
            Some(std::path::Path::new("/dev/hidraw17"))
        );
        assert_eq!(
            devs[0].reader.as_deref(),
            Some("Yubico YubiKey OTP+FIDO+CCID 00 00")
        );
        assert!(devs[0].caps.has(Caps::FIDO2) && devs[0].caps.has(Caps::OATH));
    }

    #[test]
    fn reported_topology_is_unaffected_by_the_contention_rule() {
        // Same two Yubico keys, but on a backend that reports bus+address (the
        // sysfs path): pass 1 settles ownership on hard evidence, so the tie
        // never arises and the card key keeps its own FIDO node in either order.
        for fido_only_first in [true, false] {
            let probes = [probe(
                "Yubico YubiKey OTP+FIDO+CCID 00 00",
                false,
                true,
                false,
                false,
                Some("11111111"),
                Some(9),
                Some(16),
            )];
            let card_sibling = hid(0x1050, 0x0407, "/dev/hidraw17", None, Some(9), Some(16));
            let fido_only = hid(0x1050, 0x0406, "/dev/hidraw18", None, Some(9), Some(20));
            let hids = if fido_only_first {
                [fido_only, card_sibling]
            } else {
                [card_sibling, fido_only]
            };
            let devs = correlate(&hids, &probes, &Keyring::default());
            assert_eq!(devs.len(), 2, "two physical keys must stay two devices");
            let card = devs
                .iter()
                .find(|d| d.reader.is_some())
                .expect("the card key keeps its reader");
            assert_eq!(
                card.hid_path.as_deref(),
                Some(std::path::Path::new("/dev/hidraw17")),
                "the reader-backed row must carry its OWN FIDO node \
                 (fido_only_first = {fido_only_first})"
            );
            assert_eq!(card.serial, "11111111");
            let alone = devs
                .iter()
                .find(|d| d.reader.is_none())
                .expect("the FIDO-only key stands alone");
            assert_eq!(
                alone.hid_path.as_deref(),
                Some(std::path::Path::new("/dev/hidraw18"))
            );
            assert!(alone.serial.is_empty());
        }
    }
}

#[cfg(test)]
mod plan_tests {
    use super::*;

    fn caps(bits: &[Caps]) -> Caps {
        let mut c = Caps::default();
        for b in bits {
            c.insert(*b);
        }
        c
    }

    #[test]
    fn plan_is_ordered_and_only_present_applets() {
        let full = caps(&[Caps::OATH, Caps::PGP, Caps::PIV, Caps::OTP, Caps::FIDO2]);
        assert_eq!(
            factory_reset_plan(full),
            vec![
                ResetStep::Oath,
                ResetStep::OpenPgp,
                ResetStep::Token2Otp,
                ResetStep::Piv,
                ResetStep::Fido,
            ]
        );
    }

    #[test]
    fn fido_is_always_last_when_present() {
        let c = caps(&[Caps::FIDO2, Caps::OATH]);
        let plan = factory_reset_plan(c);
        assert_eq!(plan.last(), Some(&ResetStep::Fido));
        assert_eq!(plan, vec![ResetStep::Oath, ResetStep::Fido]);
    }

    #[test]
    fn absent_applets_are_omitted() {
        let c = caps(&[Caps::PIV]);
        assert_eq!(factory_reset_plan(c), vec![ResetStep::Piv]);
        // TOTP (Molto2) and PROG are not applet-reset steps here.
        assert_eq!(
            factory_reset_plan(caps(&[Caps::TOTP])),
            Vec::<ResetStep>::new()
        );
        assert_eq!(factory_reset_plan(Caps::default()), Vec::<ResetStep>::new());
    }

    #[test]
    fn piv_sits_immediately_before_fido_not_with_the_other_card_applets() {
        let plan = factory_reset_plan(caps(&[
            Caps::OATH,
            Caps::PGP,
            Caps::PIV,
            Caps::OTP,
            Caps::FIDO2,
        ]));
        let piv_idx = plan.iter().position(|s| *s == ResetStep::Piv).unwrap();
        assert_eq!(plan[piv_idx + 1], ResetStep::Fido);
    }

    #[test]
    fn exclude_unresettable_piv_removes_just_the_piv_step() {
        let mut plan = factory_reset_plan(caps(&[Caps::OATH, Caps::PIV, Caps::FIDO2]));
        exclude_unresettable_piv(&mut plan);
        assert_eq!(plan, vec![ResetStep::Oath, ResetStep::Fido]);
    }

    #[test]
    fn exclude_unresettable_piv_is_a_no_op_without_a_piv_step() {
        let mut plan = factory_reset_plan(caps(&[Caps::OATH, Caps::FIDO2]));
        let before = plan.clone();
        exclude_unresettable_piv(&mut plan);
        assert_eq!(plan, before);
    }

    #[test]
    fn labels_are_stable() {
        assert_eq!(ResetStep::Oath.label(), "OATH");
        assert_eq!(ResetStep::OpenPgp.label(), "OpenPGP");
        assert_eq!(ResetStep::Piv.label(), "PIV");
        assert_eq!(ResetStep::Token2Otp.label(), "OTP");
        assert_eq!(ResetStep::Fido.label(), "FIDO2");
    }
}
