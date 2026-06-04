# Branch bundle — device-centric redesign

This bundle contains **real, compile-ready Rust** at its actual repo path, ready
to land on a branch so your local Claude Code CLI can build + test against
hardware. It is **not** a finished UI — it's the safe, hardware-independent
foundation (palette, fonts, painters, help system) plus a precise plan for the
part that needs real keys (the unified device model).

## What's in here
```
crates/keyroost/src/ui/
  mod.rs      — module root; help_popover() + scrim, help_button(), badge
  theme.rs    — Palette (dark/light + accents), install_fonts, button/pill/
                status_dot/ring/segmented/card_frame, totp_window
  help.rs     — plain-language help content table + LEARN_BASE/learn_url
```
All three depend only on **egui/eframe 0.29 + std** — they compile with no keys
plugged in and don't touch the protocol crates.

## Create the branch
From the repo root:
```bash
git checkout -b redesign/device-centric-ui
cp -r /path/to/branch_bundle/crates .      # lands files at crates/keyroost/src/ui/
git add crates/keyroost/src/ui
git commit -m "ui: add theme, help content, and popover primitives (no behavior change yet)"
```
Then wire the module in (see next section), build, and iterate. Push when green:
```bash
git push -u origin redesign/device-centric-ui
```

## Wire-up (small edits to main.rs)
1. Declare the module near the top of `crates/keyroost/src/main.rs`:
   ```rust
   mod ui;
   use ui::theme::{self, Palette, Mode};
   ```
2. Add redesign state to your `App` struct:
   ```rust
   mode: Mode,                       // default Mode::Dark
   accent: egui::Color32,            // default Palette::ACCENTS[0]
   selected: Option<DeviceId>,
   cap_tab: CapTab,                  // Overview | Fido2 | Oath | Pgp | Piv
   log_open: bool,
   help_open: Option<&'static str>,  // topic id; None = closed
   help_anchor: egui::Pos2,
   ```
3. In `App::new(cc)`: `theme::install_fonts(&cc.egui_ctx);`
   (or skip to use default fonts until you vendor the TTFs — see theme.rs).
4. At the top of `update()`:
   ```rust
   let p = Palette::new(self.mode, self.accent);
   p.apply(ctx, self.mode);
   ```
5. At the **end** of `update()`, render help if open:
   ```rust
   if let Some(topic) = self.help_open {
       if ui::help_popover(ctx, &p, topic, self.help_anchor) {
           self.help_open = None;
       }
   }
   ```
6. Anywhere you want a "?": 
   ```rust
   let r = ui::help_button(ui, &p, self.help_open == Some("oath"));
   if r.clicked() {
       self.help_anchor = r.rect.left_bottom();
       self.help_open = if self.help_open == Some("oath") { None } else { Some("oath") };
   }
   ```

After these, it still looks like today's app (no visual change) but with the new
theme applied and the help system live. Commit that as a known-good checkpoint
before the bigger refactor.

## The actual work (build locally, test with keys) — in order
These need the real device model and/or applet handles, so they live with your
build-test loop, not in this bundle. The egui recipes + screen specs are in
`design_handoff_egui_impl/README.md` (same project); the screenshots there are
the visual source of truth.

1. **Unified `UiDevice` model — the hard part.** The device sidebar must list each
   *physical* key once with merged capability badges. Today HID (FIDO) and PC/SC
   (OATH/PGP/PIV/Molto2) enumerate separately and the same YubiKey shows up
   twice. Use **`keyroost-resolve`** (already in the workspace, built for exactly
   this USB/CCID correlation) to merge them:
   ```rust
   struct UiDevice {
       id: DeviceId, vendor: String, model: String, serial: String,
       transport: String, firmware: String,
       caps: Caps,            // bitflags FIDO2|OATH|PGP|PIV|TOTP
       kind: DeviceKind,      // Key | Token(Molto2)
       // handles to reach each applet (hidraw path, pcsc reader name, …)
   }
   ```
   Everything below is a thin layer over `Vec<UiDevice>` + `selected`.
2. **Panel skeleton:** `TopBottomPanel::top` (bar) · `SidePanel::left` (286px
   devices) · `TopBottomPanel::bottom` (log, when `log_open`) · `CentralPanel`.
3. **Device rows** (selectable; recipe in the README), **hero**, **capability
   tabs** (`Overview` + one per cap).
4. **Overview** tab (stacked summary cards with `Manage →` jumps).
5. **Port existing applet panels** into `cap_tab` branches — FIDO2 (PIN, resident
   creds, reset), OATH (use `theme::ring` + `theme::totp_window`), OpenPGP, PIV.
   Keep all current worker/logic; only the presentation moves.
6. **Molto2** distinct view: `brand_soft` hero band, customer-key strip,
   scrollable 100-slot rail + editor with `theme::segmented` in **brand** color.
7. **Global activity log** drawer (replaces the Molto2-only one).
8. **Empty / first-run** state.

## Notes / gotchas
- `Palette::apply(ctx, mode)` takes the mode explicitly (picks the right egui base
  Visuals). Call it every frame — it's cheap.
- egui has **no letter-spacing**; drop the prototype's slight title tracking.
- `help_popover` pre-solves the `Area`-is-transparent trap (its content is wrapped
  in a filled `Frame`). If you build other floating UI, do the same.
- Signatures here target **egui 0.29** (`Margin::same(f32)`, `Rounding::same(f32)`,
  `Shadow { offset, blur, spread, color }`). If you bump egui, expect minor
  churn in these calls.
- Fonts add ~1–2MB unsubsetted; subset to Latin or defer `install_fonts` to keep
  the binary lean.

## Verify
`cargo build --release -p keyroost` and `cargo run -p keyroost` on hardware; keep
`cargo test --workspace --offline` green. Don't modify the protocol crates.
```
```
