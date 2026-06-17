// crates/keyroost/src/ui/mod.rs
//
// UI module for the device-centric redesign. Add `mod ui;` to main.rs.
//
// What's pre-built and compile-ready here:
//   theme   — Palette (dark/light + accents), fonts, button/pill/dot/ring/segmented
//   help    — plain-language help content + LEARN_BASE
//   help_popover() — the "?" popover with dimmed backdrop (Area layering pre-solved)
//
// What's intentionally NOT here (needs the unified device model + real applet
// handles, so it belongs with the local build-test loop): the device sidebar
// rows, hero, capability tabs, and the per-capability panels. Build those in
// main.rs (or a `screens` submodule) on top of these primitives — see BRANCH.md.

pub mod aaguid;
pub mod device;
pub mod help;
pub mod mds;
pub mod theme;

use theme::{f_bold, f_reg, Palette};

/// Render the help popover for `topic` anchored under `anchor` (use the clicked
/// "?" button's `response.rect.left_bottom()`), over a dimmed click-to-close
/// backdrop. Returns true if the user dismissed it (click-away or Esc) — the
/// caller should then set its `help_open` state to None.
///
/// The key gotcha this pre-solves: egui `Area`s are transparent by default, so a
/// naive popover renders as invisible text over the UI. Here the panel content is
/// always wrapped in a filled `Frame` (fill = palette.pop), which is the egui
/// equivalent of the prototype bug where the popover rendered outside the themed
/// container.
pub fn help_popover(ctx: &egui::Context, p: &Palette, topic: &str, anchor: egui::Pos2) -> bool {
    let Some(h) = help::help(topic) else {
        return true; // unknown topic -> treat as closed
    };

    let mut dismissed = false;
    let screen = ctx.screen_rect();

    // --- dimmed backdrop (Middle layer): click anywhere to close ---
    egui::Area::new(egui::Id::new("help_scrim"))
        .order(egui::Order::Middle)
        .fixed_pos(screen.min)
        .interactable(true)
        .show(ctx, |ui| {
            ui.painter()
                .rect_filled(screen, 0.0, egui::Color32::from_black_alpha(97));
            if ui.allocate_rect(screen, egui::Sense::click()).clicked() {
                dismissed = true;
            }
        });

    // --- panel (Foreground layer): caret + title + body + Learn link ---
    let width = 300.0;
    let x = (anchor.x).min(screen.right() - width - 12.0).max(12.0);
    let pos = egui::pos2(x, anchor.y + 7.0);

    egui::Area::new(egui::Id::new("help_pop"))
        .order(egui::Order::Foreground)
        .fixed_pos(pos)
        .show(ctx, |ui| {
            ui.set_max_width(width);
            egui::Frame {
                inner_margin: egui::Margin::same(16.0),
                rounding: egui::Rounding::same(13.0),
                fill: p.pop,
                stroke: egui::Stroke::new(1.0, p.line),
                shadow: egui::epaint::Shadow {
                    offset: egui::vec2(0.0, 12.0),
                    blur: 40.0,
                    spread: 0.0,
                    color: egui::Color32::from_black_alpha(115),
                },
                ..Default::default()
            }
            .show(ui, |ui| {
                ui.set_max_width(width - 32.0);
                // title row
                ui.horizontal(|ui| {
                    badge_q(ui, p);
                    ui.add_space(2.0);
                    ui.label(egui::RichText::new(h.title).font(f_bold(13.5)).color(p.txt));
                });
                ui.add_space(6.0);
                // body — wraps to the frame width
                ui.label(egui::RichText::new(h.body).font(f_reg(13.0)).color(p.txt));
                ui.add_space(10.0);
                ui.hyperlink_to(
                    egui::RichText::new("Learn how to use this  ↗")
                        .font(theme::f_sb(12.5))
                        .color(p.accent),
                    help::learn_url(h.slug),
                );
            });
        });

    if ctx.input(|i| i.key_pressed(egui::Key::Escape)) {
        dismissed = true;
    }
    dismissed
}

/// The little filled "?" disc used in popover titles and (inline) as the
/// clickable affordance. For the clickable one, wrap a copy in a Button/Sense.
fn badge_q(ui: &mut egui::Ui, p: &Palette) {
    let d = 18.0;
    let (rect, _) = ui.allocate_exact_size(egui::vec2(d, d), egui::Sense::hover());
    ui.painter().circle_filled(rect.center(), d / 2.0, p.accent);
    ui.painter().text(
        rect.center(),
        egui::Align2::CENTER_CENTER,
        "?",
        theme::f_bold(11.0),
        p.accent_ink,
    );
}

/// A clickable "?" affordance. Returns its Response; on click, the caller records
/// `response.rect.left_bottom()` as the popover anchor and toggles help_open.
///
///   let r = help_button(ui, &p, help_open == Some("oath"));
///   if r.clicked() { anchor = r.rect.left_bottom();
///       help_open = if help_open == Some("oath") { None } else { Some("oath") }; }
pub fn help_button(ui: &mut egui::Ui, p: &Palette, active: bool) -> egui::Response {
    let d = 17.0;
    let (rect, resp) = ui.allocate_exact_size(egui::vec2(d, d), egui::Sense::click());
    let (fill, fg) = if active || resp.hovered() {
        (p.accent, p.accent_ink)
    } else {
        (p.accent_soft(), p.accent)
    };
    ui.painter().circle_filled(rect.center(), d / 2.0, fill);
    ui.painter().text(
        rect.center(),
        egui::Align2::CENTER_CENTER,
        "?",
        theme::f_bold(10.5),
        fg,
    );
    resp.on_hover_text("What's this?")
}
