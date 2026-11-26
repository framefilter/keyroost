//! The Vault tab: the FIDO2 password vault on the selected key, beside
//! Authenticator, and the "Password vault" card on the key's Overview.
//!
//! The tab is offered only on keys that can hold a vault, the way
//! Authenticator and OpenPGP are offered only on keys that have them; the
//! Overview card says why a key can't. The vault is experimental, so both
//! carry [`experimental_note`].
//!
//! The words are the CLI's (`keyroostctl fido vault`), fitted to the layout.

use keyroost_ctap::AuthenticatorInfo;
use keyroost_transport::vault::{self, VaultKeyError, VaultOnKey};

use crate::ui::device::CapTab;
use crate::ui::theme::{self, BtnKind, Palette};
use crate::{fido_unread_line, sanitize_title, App, TypedSecrets};

/// Where problems are reported: the CLI help's URL.
pub(crate) const ISSUES_URL: &str = "https://github.com/framefilter/keyroost/issues";

/// Whether the selected key is offered a vault, from what is known of it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum VaultOffer {
    /// No getInfo answer yet (still reading, or the read failed).
    Unknown,
    /// Windows without administrator rights: FIDO access is gated, so
    /// getInfo never arrives.
    NeedsAdmin,
    /// The key can hold a vault.
    Ready,
    /// The key could hold a vault but has no PIN set.
    NeedsPin,
    /// The key cannot hold a vault: it lacks what is named.
    No(&'static str),
}

/// What `info` (the key's getInfo, `None` until read) says about a vault.
/// A key with no CTAP2 interface (`u2f_only`) can't hold one; without
/// getInfo, a Windows session without administrator rights (`non_admin`)
/// is told so, others wait for the read.
pub(crate) fn vault_offer(
    info: Option<&AuthenticatorInfo>,
    u2f_only: bool,
    non_admin: bool,
) -> VaultOffer {
    if u2f_only {
        return VaultOffer::No("CTAP2");
    }
    let Some(info) = info else {
        return if non_admin {
            VaultOffer::NeedsAdmin
        } else {
            VaultOffer::Unknown
        };
    };
    match vault::check_support(info) {
        Ok(()) => VaultOffer::Ready,
        Err(VaultKeyError::PinNotSet) => VaultOffer::NeedsPin,
        Err(VaultKeyError::Unsupported(what)) => VaultOffer::No(what),
        // `check_support` answers with the two above today. A refusal it
        // adds later is still a refusal: never a key left on "Reading key…".
        Err(_) => VaultOffer::No("everything a vault needs"),
    }
}

/// The key's tabs with Vault added when it is offered: on a key with a
/// FIDO2 tab, right after Authenticator, else right after FIDO2. A key
/// still being read (`Unknown`, `NeedsAdmin`) keeps it, so a remembered
/// Vault pick isn't snapped away before getInfo lands.
pub(crate) fn with_vault_tab(mut tabs: Vec<CapTab>, offer: VaultOffer) -> Vec<CapTab> {
    if matches!(offer, VaultOffer::No(_)) {
        return tabs;
    }
    let anchor = tabs
        .iter()
        .position(|t| *t == CapTab::Oath)
        .or_else(|| tabs.iter().position(|t| *t == CapTab::Fido2));
    if tabs.contains(&CapTab::Fido2) {
        if let Some(i) = anchor {
            tabs.insert(i + 1, CapTab::Vault);
        }
    }
    tabs
}

/// `1 entry` / `N entries`: the app's copy of the CLI's helper.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the vault's list and messages count entries with it"
    )
)]
pub(crate) fn entries(n: usize) -> String {
    if n == 1 {
        "1 entry".to_owned()
    } else {
        format!("{n} entries")
    }
}

/// A vault's name as the app shows it: control characters flattened,
/// `(unnamed)` when it has none.
fn shown_name(name: Option<&str>) -> String {
    match name {
        Some(n) if !n.is_empty() => sanitize_title(n),
        _ => "(unnamed)".to_owned(),
    }
}

/// A vault as its chip names it: `Personal · 12`, or
/// `Personal · (unavailable)` when it did not open.
pub(crate) fn chip_label(v: &VaultOnKey) -> String {
    let name = shown_name(v.vault_ref.name.as_deref());
    match v.entry_count() {
        Some(n) => format!("{name} \u{00B7} {n}"),
        None => format!("{name} \u{00B7} (unavailable)"),
    }
}

/// Upper-case the first letter of a CLI message, as a sentence starts.
fn sentence(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(first) => first.to_uppercase().chain(c).collect(),
        None => String::new(),
    }
}

/// The Overview card's line: why there is no vault, or what is in it.
/// `read_failed` is whether the key's getInfo read failed (the FIDO2 tab's
/// "Couldn't read this key."); `vaults` is the unlocked list, `None` while
/// locked.
pub(crate) fn overview_line(
    offer: VaultOffer,
    read_failed: bool,
    vaults: Option<&[VaultOnKey]>,
) -> String {
    match offer {
        VaultOffer::Unknown => fido_unread_line(false, read_failed).to_owned(),
        VaultOffer::NeedsAdmin => "Open the FIDO2 tab to manage this key via Windows settings \
                                   or restart as administrator."
            .to_owned(),
        VaultOffer::No(what) => format!(
            "{}.",
            sentence(&VaultKeyError::Unsupported(what).to_string())
        ),
        VaultOffer::NeedsPin => {
            "A password vault needs a FIDO2 PIN; set one on the FIDO2 tab.".to_owned()
        }
        VaultOffer::Ready => match vaults {
            None => "Passwords in an encrypted vault on this key, opened with the PIN and a touch."
                .to_owned(),
            Some([]) => "No vaults on this key yet.".to_owned(),
            Some(vs) => vs.iter().map(chip_label).collect::<Vec<_>>().join(", "),
        },
    }
}

/// The "Experimental" pill and the line asking for reports and a backup.
pub(crate) fn experimental_note(ui: &mut egui::Ui, p: &Palette) {
    ui.horizontal_wrapped(|ui| {
        ui.spacing_mut().item_spacing.x = 0.0;
        theme::pill(ui, "Experimental", p.warn, p.warn_soft());
        ui.add_space(8.0);
        let text = |s: &str| {
            egui::Label::new(
                egui::RichText::new(s)
                    .font(theme::f_reg(11.5))
                    .color(p.txt3),
            )
        };
        ui.add(text("Experimental: please "));
        ui.hyperlink_to(
            egui::RichText::new("report problems").font(theme::f_reg(11.5)),
            ISSUES_URL,
        );
        ui.add(text(" and keep a backup."));
    });
}

/// The Vault tab's state for the selected key. Replaced whole when another
/// key is selected.
#[derive(Default)]
pub(crate) struct VaultState {
    /// The last failure, shown under the header.
    pub(crate) error: Option<String>,
    /// The last success, shown under the header.
    pub(crate) info: Option<String>,
}

impl TypedSecrets for VaultState {
    fn secrets_mut(&mut self) -> Vec<&mut String> {
        Vec::new()
    }
}

impl App {
    /// The Vault tab.
    pub(crate) fn cap_vault(&mut self, ui: &mut egui::Ui, p: &Palette) {
        let offer = self.vault_offer();
        let mut open_fido2 = false;
        theme::card_frame(p).show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new("Vault")
                        .font(theme::f_sb(14.5))
                        .color(p.txt),
                );
                ui.add_space(6.0);
                self.help_dot(ui, p, "vault");
            });
            ui.add_space(6.0);
            experimental_note(ui, p);
            if offer == VaultOffer::Ready {
                return;
            }
            ui.add_space(8.0);
            if offer == VaultOffer::NeedsAdmin {
                theme::pill(ui, "Administrator rights needed", p.warn, p.warn_soft());
                ui.add_space(6.0);
            }
            ui.label(
                egui::RichText::new(overview_line(
                    offer,
                    self.security_keys.error.is_some(),
                    None,
                ))
                .font(theme::f_reg(13.0))
                .color(if offer == VaultOffer::Unknown {
                    p.txt3
                } else {
                    p.txt2
                }),
            );
            if matches!(offer, VaultOffer::NeedsAdmin | VaultOffer::NeedsPin) {
                ui.add_space(8.0);
                open_fido2 = theme::button(ui, p, BtnKind::Default, "Open FIDO2").clicked();
            }
        });
        if open_fido2 {
            self.cap_tab = CapTab::Fido2;
        }
        ui.add_space(12.0);
        if let Some(info) = &self.vault.info {
            ui.colored_label(p.ok, info);
            ui.add_space(6.0);
        }
        if let Some(err) = &self.vault.error {
            ui.colored_label(p.err, err);
            ui.add_space(6.0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keyroost_transport::vault::fake::FakeKey;
    use keyroost_transport::vault::{unlock, VaultAuth, VaultProblem, VaultRef};
    use keyroost_vault::{Entry, Vault};
    use zeroize::Zeroizing;

    fn entry(title: &str) -> Entry {
        Entry {
            id: keyroost_vault::new_id(),
            title: title.into(),
            username: "alice".into(),
            password: Zeroizing::new("hunter22".into()),
            url: String::new(),
            notes: String::new(),
            modified_minutes: 29_000_000,
        }
    }

    /// The vaults one unlock of `key` opens.
    fn unlocked(key: &mut FakeKey) -> Vec<VaultOnKey> {
        let mut auth = VaultAuth::pin(Zeroizing::new(FakeKey::PIN.to_owned()));
        unlock(key, &mut auth, &mut |_| {}).unwrap().vaults
    }

    fn unavailable(name: Option<&str>) -> VaultOnKey {
        VaultOnKey {
            vault_ref: VaultRef {
                credential_id: vec![1, 2, 3],
                name: name.map(str::to_owned),
            },
            state: Err(VaultProblem::NoSecret),
        }
    }

    fn info_with(f: impl FnOnce(&mut AuthenticatorInfo)) -> AuthenticatorInfo {
        let mut info = FakeKey::new().info;
        f(&mut info);
        info
    }

    #[test]
    fn vault_offer_reads_get_info() {
        let full = FakeKey::new().info;
        assert_eq!(vault_offer(Some(&full), false, false), VaultOffer::Ready);
        let no_pin = info_with(|i| {
            for (k, v) in &mut i.options {
                if k == "clientPin" {
                    *v = false;
                }
            }
        });
        assert_eq!(
            vault_offer(Some(&no_pin), false, false),
            VaultOffer::NeedsPin
        );
        let no_lbk = info_with(|i| i.extensions.retain(|e| e != "largeBlobKey"));
        assert_eq!(
            vault_offer(Some(&no_lbk), false, false),
            VaultOffer::No("largeBlobKey")
        );
        assert_eq!(vault_offer(None, false, false), VaultOffer::Unknown);
        assert_eq!(vault_offer(None, false, true), VaultOffer::NeedsAdmin);
        assert_eq!(vault_offer(None, true, false), VaultOffer::No("CTAP2"));
        assert_eq!(
            vault_offer(Some(&full), true, false),
            VaultOffer::No("CTAP2")
        );
    }

    #[test]
    fn vault_tab_sits_beside_authenticator() {
        use CapTab::*;
        assert_eq!(
            with_vault_tab(vec![Overview, Fido2, Oath, Pgp], VaultOffer::Ready),
            vec![Overview, Fido2, Oath, Vault, Pgp]
        );
        assert_eq!(
            with_vault_tab(vec![Overview, Fido2, Pgp, Piv], VaultOffer::Ready),
            vec![Overview, Fido2, Vault, Pgp, Piv]
        );
        assert_eq!(
            with_vault_tab(vec![Overview, Fido2, Oath], VaultOffer::No("CTAP2")),
            vec![Overview, Fido2, Oath]
        );
        // No FIDO2 tab (a U2F-only key, a card-only key): no vault.
        assert_eq!(
            with_vault_tab(vec![Overview, Oath, Piv], VaultOffer::Ready),
            vec![Overview, Oath, Piv]
        );
        for offer in [
            VaultOffer::Unknown,
            VaultOffer::NeedsAdmin,
            VaultOffer::NeedsPin,
        ] {
            assert_eq!(
                with_vault_tab(vec![Overview, Fido2], offer),
                vec![Overview, Fido2, Vault],
                "{offer:?}"
            );
        }
    }

    #[test]
    fn a_remembered_vault_tab_survives_until_info_loads() {
        use CapTab::*;
        let tabs = || vec![Overview, Fido2, Oath];
        assert_eq!(
            crate::snap_cap_tab(Vault, &with_vault_tab(tabs(), VaultOffer::Unknown)),
            Vault
        );
        assert_eq!(
            crate::snap_cap_tab(Vault, &with_vault_tab(tabs(), VaultOffer::No("a PIN"))),
            Overview
        );
    }

    #[test]
    fn overview_line_says_why() {
        assert_eq!(
            overview_line(VaultOffer::Unknown, false, None),
            "Reading key\u{2026}"
        );
        // A failed read isn't left on "Reading key…".
        assert_eq!(
            overview_line(VaultOffer::Unknown, true, None),
            "Couldn't read this key."
        );
        assert_eq!(
            overview_line(VaultOffer::NeedsAdmin, false, None),
            "Open the FIDO2 tab to manage this key via Windows settings or restart as \
             administrator."
        );
        assert_eq!(
            overview_line(VaultOffer::No("largeBlobKey"), false, None),
            "This key cannot hold a password vault: it does not support largeBlobKey."
        );
        assert_eq!(
            overview_line(VaultOffer::NeedsPin, false, None),
            "A password vault needs a FIDO2 PIN; set one on the FIDO2 tab."
        );
        assert_eq!(
            overview_line(VaultOffer::Ready, false, None),
            "Passwords in an encrypted vault on this key, opened with the PIN and a touch."
        );
        assert_eq!(
            overview_line(VaultOffer::Ready, false, Some(&[])),
            "No vaults on this key yet."
        );
        let mut key = FakeKey::new();
        key.add_vault(
            "Personal",
            &Vault {
                entries: vec![entry("GitHub"), entry("Bank")],
            },
        );
        key.add_vault("Work", &Vault::default());
        let vaults = unlocked(&mut key);
        assert_eq!(
            overview_line(VaultOffer::Ready, false, Some(&vaults)),
            "Personal \u{00B7} 2, Work \u{00B7} 0"
        );
    }

    #[test]
    fn chip_labels_and_entries() {
        let mut key = FakeKey::new();
        key.add_vault(
            "Personal",
            &Vault {
                entries: (0..12).map(|i| entry(&format!("Site {i}"))).collect(),
            },
        );
        let unnamed = key.add_credential(keyroost_vault::unnamed_user_handle().unwrap(), None);
        key.put_vault(&unnamed, &Vault::default());
        let vaults = unlocked(&mut key);
        assert_eq!(chip_label(&vaults[0]), "Personal \u{00B7} 12");
        assert_eq!(chip_label(&vaults[1]), "(unnamed) \u{00B7} 0");
        assert_eq!(
            chip_label(&unavailable(None)),
            "(unnamed) \u{00B7} (unavailable)"
        );
        assert_eq!(
            chip_label(&unavailable(Some(""))),
            "(unnamed) \u{00B7} (unavailable)"
        );
        assert_eq!(
            chip_label(&unavailable(Some("Work"))),
            "Work \u{00B7} (unavailable)"
        );
        // A name from the key can't break the line.
        assert_eq!(
            chip_label(&unavailable(Some("a\u{1b}[2Jb"))),
            "a [2Jb \u{00B7} (unavailable)"
        );
        assert_eq!(entries(0), "0 entries");
        assert_eq!(entries(1), "1 entry");
        assert_eq!(entries(12), "12 entries");
    }

    #[test]
    fn the_vault_help_topic_exists() {
        let h = crate::ui::help::help("vault").expect("a vault help topic");
        assert_eq!(h.title, "Password vault");
        assert!(h.body.contains("keep a backup file"), "{}", h.body);
    }
}
