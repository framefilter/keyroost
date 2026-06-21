// crates/keyroost/src/ui/theme.rs
//
// Device-centric redesign — palette, fonts, and small egui paint helpers.
// Self-contained: depends only on egui/eframe 0.29 + std. Compiles without any
// hardware present, so it is safe to land on the branch ahead of the
// device-model work. Values mirror the HTML prototype exactly.
//
// Wire-up (in main.rs):
//   mod ui;                          // -> ui/mod.rs
//   use ui::theme::{Palette, Mode, install_fonts, f_bold, f_sb, f_reg, f_mono};
//   // in App::new(cc):  install_fonts(&cc.egui_ctx);
//   // each frame (or on change):  self.palette().apply(ctx);

use egui::{Color32, FontFamily, FontId, Margin, Response, Rounding, Stroke};

#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub enum Mode {
    #[default]
    Dark,
    Light,
}

#[derive(Clone, Copy)]
pub struct Palette {
    // part of the palette API; not yet used
    #[allow(dead_code)]
    pub stage: Color32, // window backdrop / behind cards
    pub surface: Color32, // main + central panel fill
    pub bar: Color32,     // top bar / log drawer
    pub side: Color32,    // device sidebar
    pub panel: Color32,   // cards
    pub raised: Color32,  // inputs
    pub raised2: Color32, // chips / hover
    pub pop: Color32,     // popovers / callouts
    pub line: Color32,
    pub line_soft: Color32,
    pub txt: Color32,
    pub txt2: Color32,
    pub txt3: Color32,
    pub accent: Color32,
    pub accent_ink: Color32,
    pub brand: Color32, // logo / Molto2 token
    pub ok: Color32,
    pub warn: Color32,
    pub err: Color32,
}

/// rgba tint at the given alpha (0..=255) — replaces CSS color-mix / rgba().
pub fn tint(c: Color32, a: u8) -> Color32 {
    Color32::from_rgba_unmultiplied(c.r(), c.g(), c.b(), a)
}

/// Blend `c` toward white by `t` (0..1). Used for button hover states.
pub fn lighten(c: Color32, t: f32) -> Color32 {
    let t = t.clamp(0.0, 1.0);
    let mix = |x: u8| (x as f32 + (255.0 - x as f32) * t).round() as u8;
    Color32::from_rgb(mix(c.r()), mix(c.g()), mix(c.b()))
}

/// Blend `c` toward black by `t` (0..1). Used for button pressed states.
pub fn darken(c: Color32, t: f32) -> Color32 {
    let t = t.clamp(0.0, 1.0);
    let mix = |x: u8| (x as f32 * (1.0 - t)).round() as u8;
    Color32::from_rgb(mix(c.r()), mix(c.g()), mix(c.b()))
}

impl Palette {
    pub fn new(mode: Mode, accent: Color32, colorblind: bool) -> Self {
        let mut p = match mode {
            Mode::Dark => Palette {
                stage: Color32::from_rgb(0x0f, 0x11, 0x15),
                surface: Color32::from_rgb(0x18, 0x1b, 0x21),
                bar: Color32::from_rgb(0x13, 0x16, 0x1b),
                side: Color32::from_rgb(0x15, 0x18, 0x1d),
                panel: Color32::from_rgb(0x1c, 0x20, 0x26),
                raised: Color32::from_rgb(0x23, 0x28, 0x30),
                raised2: Color32::from_rgb(0x2a, 0x31, 0x3a),
                pop: Color32::from_rgb(0x2c, 0x33, 0x3d),
                line: Color32::from_rgb(0x2b, 0x32, 0x3c),
                line_soft: Color32::from_rgb(0x22, 0x28, 0x31),
                txt: Color32::from_rgb(0xe8, 0xea, 0xee),
                txt2: Color32::from_rgb(0x9a, 0xa2, 0xad),
                txt3: Color32::from_rgb(0x64, 0x6c, 0x78),
                accent,
                accent_ink: Color32::WHITE,
                brand: Color32::from_rgb(0xf0, 0x8c, 0x3c),
                ok: Color32::from_rgb(0x5f, 0xcf, 0x83),
                warn: Color32::from_rgb(0xe3, 0xb5, 0x52),
                err: Color32::from_rgb(0xe7, 0x6d, 0x6d),
            },
            Mode::Light => Palette {
                stage: Color32::from_rgb(0xda, 0xdd, 0xe3),
                surface: Color32::from_rgb(0xf6, 0xf7, 0xf9),
                bar: Color32::from_rgb(0xec, 0xee, 0xf2),
                side: Color32::from_rgb(0xee, 0xf0, 0xf4),
                panel: Color32::from_rgb(0xff, 0xff, 0xff),
                raised: Color32::from_rgb(0xf1, 0xf3, 0xf7),
                raised2: Color32::from_rgb(0xe7, 0xea, 0xf0),
                pop: Color32::from_rgb(0xff, 0xff, 0xff),
                line: Color32::from_rgb(0xdd, 0xe1, 0xe8),
                line_soft: Color32::from_rgb(0xe9, 0xec, 0xf1),
                txt: Color32::from_rgb(0x1b, 0x1f, 0x26),
                txt2: Color32::from_rgb(0x5a, 0x62, 0x6d),
                txt3: Color32::from_rgb(0x94, 0x9b, 0xa6),
                accent,
                accent_ink: Color32::WHITE,
                brand: Color32::from_rgb(0xe0, 0x80, 0x1c),
                ok: Color32::from_rgb(0x1f, 0x9b, 0x54),
                warn: Color32::from_rgb(0xc0, 0x85, 0x0f),
                err: Color32::from_rgb(0xd3, 0x45, 0x36),
            },
        };
        p.accent = accent;
        if colorblind {
            // Color Universal Design (Okabe & Ito; Wong, Nature Methods 2011):
            // the common deficiency is red-green, so replace the green<->red
            // success/error pair with a blue<->vermillion pair that stays
            // distinguishable under deuteran, protan and tritan vision. Warn
            // (amber), backgrounds, accent and brand are left as-is.
            match mode {
                Mode::Dark => {
                    p.ok = Color32::from_rgb(0x56, 0xb4, 0xe9); // sky blue
                    p.err = Color32::from_rgb(0xe8, 0x59, 0x0c); // vermillion
                }
                Mode::Light => {
                    p.ok = Color32::from_rgb(0x00, 0x72, 0xb2); // blue
                    p.err = Color32::from_rgb(0xd5, 0x5e, 0x00); // vermillion
                }
            }
        }
        p
    }

    /// Accent options offered in the prototype (same lightness/chroma, hue only).
    pub const ACCENTS: [Color32; 3] = [
        Color32::from_rgb(0x4f, 0x90, 0xff), // blue (default)
        Color32::from_rgb(0x2b, 0xb3, 0xa3), // teal
        Color32::from_rgb(0x8b, 0x7c, 0xf0), // violet
    ];

    // Derived accent tints (replace CSS --kr-accent-soft / --kr-accent-line).
    pub fn accent_soft(&self) -> Color32 {
        tint(self.accent, 38)
    }
    // part of the palette API; not yet used
    #[allow(dead_code)]
    pub fn accent_line(&self) -> Color32 {
        tint(self.accent, 115)
    }
    pub fn brand_soft(&self) -> Color32 {
        tint(self.brand, 38)
    }
    pub fn ok_soft(&self) -> Color32 {
        tint(self.ok, 36)
    }
    pub fn warn_soft(&self) -> Color32 {
        tint(self.warn, 38)
    }
    pub fn err_soft(&self) -> Color32 {
        tint(self.err, 36)
    }

    /// Push the palette into egui Visuals so built-in widgets/text inherit it.
    /// Call whenever Mode/accent changes (cheap enough to call every frame).
    pub fn apply(&self, ctx: &egui::Context, mode: Mode) {
        let mut v = match mode {
            Mode::Dark => egui::Visuals::dark(),
            Mode::Light => egui::Visuals::light(),
        };
        v.override_text_color = Some(self.txt);
        v.window_fill = self.surface;
        v.panel_fill = self.surface;
        v.extreme_bg_color = self.raised; // text-edit backgrounds
        v.faint_bg_color = self.raised;
        v.hyperlink_color = self.accent;
        v.selection.bg_fill = tint(self.accent, 60);
        v.selection.stroke = Stroke::new(1.0, self.accent);
        v.widgets.noninteractive.bg_stroke = Stroke::new(1.0, self.line);
        v.widgets.inactive.bg_fill = self.raised2;
        v.widgets.inactive.weak_bg_fill = self.raised2;
        v.widgets.hovered.bg_fill = self.raised2;
        // Give text inputs a visible boundary. Without an explicit stroke the
        // field fill (`raised`) sits only a few shades off the card behind it,
        // so the box edge disappears and a password field looks like floating
        // dots. A 1px border on the inactive/hovered/active states fixes that in
        // every text field (PIN dialogs, PIV, config inputs) at once.
        v.widgets.inactive.bg_stroke = Stroke::new(1.0, self.line);
        v.widgets.hovered.bg_stroke = Stroke::new(1.0, lighten(self.line, 0.25));
        v.widgets.active.bg_stroke = Stroke::new(1.0, self.accent);
        v.window_rounding = Rounding::same(14.0);
        v.window_stroke = Stroke::new(1.0, self.line);
        ctx.set_visuals(v);
    }
}

// ---- font weight families ----
pub fn f_reg(size: f32) -> FontId {
    FontId::new(size, FontFamily::Proportional)
}
pub fn f_sb(size: f32) -> FontId {
    // Cached: these run dozens of times per frame, and `FontFamily::Name`
    // allocates an Arc<str> each call; cloning the cached family is one
    // refcount bump.
    static FAM: std::sync::OnceLock<FontFamily> = std::sync::OnceLock::new();
    FontId::new(
        size,
        FAM.get_or_init(|| FontFamily::Name("semibold".into()))
            .clone(),
    )
}
pub fn f_bold(size: f32) -> FontId {
    static FAM: std::sync::OnceLock<FontFamily> = std::sync::OnceLock::new();
    FontId::new(
        size,
        FAM.get_or_init(|| FontFamily::Name("bold".into())).clone(),
    )
}
pub fn f_mono(size: f32) -> FontId {
    FontId::new(size, FontFamily::Monospace)
}

/// Register IBM Plex Sans (Regular/SemiBold/Bold) + JetBrains Mono. Call once in
/// App::new. Vendor the four TTFs under crates/keyroost/assets/ (subset to Latin
/// to keep the binary small — adds ~1-2MB unsubsetted). If you'd rather not
/// bundle fonts yet, skip this call and the app uses egui's defaults; the layout
/// still works, only the typeface differs.
pub fn install_fonts(ctx: &egui::Context) {
    let mut f = egui::FontDefinitions::default();
    f.font_data.insert(
        "plex".into(),
        egui::FontData::from_static(include_bytes!("../../assets/IBMPlexSans-Regular.ttf")),
    );
    f.font_data.insert(
        "plex_sb".into(),
        egui::FontData::from_static(include_bytes!("../../assets/IBMPlexSans-SemiBold.ttf")),
    );
    f.font_data.insert(
        "plex_b".into(),
        egui::FontData::from_static(include_bytes!("../../assets/IBMPlexSans-Bold.ttf")),
    );
    f.font_data.insert(
        "jb".into(),
        egui::FontData::from_static(include_bytes!("../../assets/JetBrainsMono-Regular.ttf")),
    );
    f.families
        .entry(FontFamily::Proportional)
        .or_default()
        .insert(0, "plex".into());
    f.families
        .entry(FontFamily::Monospace)
        .or_default()
        .insert(0, "jb".into());
    f.families.insert(
        FontFamily::Name("semibold".into()),
        vec!["plex_sb".into(), "plex".into()],
    );
    f.families.insert(
        FontFamily::Name("bold".into()),
        vec!["plex_b".into(), "plex".into()],
    );
    ctx.set_fonts(f);
}

// ---- card frame ----
pub fn card_frame(p: &Palette) -> egui::Frame {
    egui::Frame {
        inner_margin: Margin::same(18.0),
        rounding: Rounding::same(14.0),
        fill: p.panel,
        stroke: Stroke::new(1.0, p.line),
        ..Default::default()
    }
}

// ---- status dot ----
pub fn status_dot(ui: &mut egui::Ui, color: Color32, d: f32) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(d, d), egui::Sense::hover());
    ui.painter().circle_filled(rect.center(), d / 2.0, color);
}

// ---- pill / badge ----
pub fn pill(ui: &mut egui::Ui, text: &str, fg: Color32, bg: Color32) {
    egui::Frame {
        inner_margin: Margin::symmetric(8.0, 2.0),
        rounding: Rounding::same(999.0),
        fill: bg,
        ..Default::default()
    }
    .show(ui, |ui| {
        ui.label(egui::RichText::new(text).font(f_sb(11.0)).color(fg));
    });
}

// ---- button variants ----
#[derive(Clone, Copy)]
pub enum BtnKind {
    Primary,
    Default,
    Ghost,
    Danger,
}

/// A themed button. Painted by hand (rather than `egui::Button`) so every kind
/// gets a visible hover lift, a pressed state, and a pointing-hand cursor —
/// making it obvious the control is interactive. Returns the Response.
pub fn button(ui: &mut egui::Ui, p: &Palette, kind: BtnKind, label: &str) -> Response {
    let (base_fill, base_fg, base_stroke) = match kind {
        BtnKind::Primary => (p.accent, p.accent_ink, Stroke::NONE),
        BtnKind::Default => (p.raised2, p.txt, Stroke::new(1.0, p.line)),
        BtnKind::Ghost => (Color32::TRANSPARENT, p.txt2, Stroke::new(1.0, p.line)),
        BtnKind::Danger => (p.err, p.accent_ink, Stroke::NONE),
    };

    let font = f_sb(13.0);
    let galley = ui.painter().layout_no_wrap(label.to_owned(), font, base_fg);
    let pad_x = 14.0;
    let size = egui::vec2(galley.size().x + pad_x * 2.0, 32.0);
    let (rect, resp) = ui.allocate_exact_size(size, egui::Sense::click());

    let pressed = resp.is_pointer_button_down_on();
    let hovered = resp.hovered();
    // Fill: darken on press, lift on hover. Ghost/Default gain a real surface on
    // hover so they stop reading as plain text.
    let fill = if pressed {
        darken(
            if matches!(kind, BtnKind::Ghost) {
                p.raised2
            } else {
                base_fill
            },
            0.12,
        )
    } else if hovered {
        match kind {
            BtnKind::Ghost => p.raised2,
            BtnKind::Default => lighten(base_fill, 0.10),
            _ => lighten(base_fill, 0.08),
        }
    } else {
        base_fill
    };
    // Outlined kinds pick up an accent border on hover; filled kinds keep theirs.
    let stroke = if hovered && matches!(kind, BtnKind::Default | BtnKind::Ghost) {
        Stroke::new(1.0, p.accent)
    } else {
        base_stroke
    };
    let fg = if hovered && matches!(kind, BtnKind::Ghost) {
        p.txt
    } else {
        base_fg
    };

    let painter = ui.painter();
    painter.rect(rect, Rounding::same(8.0), fill, stroke);
    let galley = painter.layout_no_wrap(label.to_owned(), f_sb(13.0), fg);
    painter.galley(rect.center() - galley.size() * 0.5, galley, fg);
    if hovered {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }
    resp
}

/// Like [`button`], but reserves room for a small icon on the left, inside the
/// button. Returns the response and the center point at which the caller should
/// paint the icon (using the returned foreground color), so the icon and label
/// read as one control. `icon_w` is the icon's box width in points.
pub fn button_with_icon(
    ui: &mut egui::Ui,
    p: &Palette,
    kind: BtnKind,
    label: &str,
    icon_w: f32,
) -> (Response, egui::Pos2, Color32) {
    let (base_fill, base_fg, base_stroke) = match kind {
        BtnKind::Primary => (p.accent, p.accent_ink, Stroke::NONE),
        BtnKind::Default => (p.raised2, p.txt, Stroke::new(1.0, p.line)),
        BtnKind::Ghost => (Color32::TRANSPARENT, p.txt2, Stroke::new(1.0, p.line)),
        BtnKind::Danger => (p.err, p.accent_ink, Stroke::NONE),
    };

    let font = f_sb(13.0);
    let galley = ui.painter().layout_no_wrap(label.to_owned(), font, base_fg);
    let pad_x = 14.0;
    let icon_gap = 6.0;
    let size = egui::vec2(
        galley.size().x + icon_w + icon_gap + pad_x * 2.0,
        32.0,
    );
    let (rect, resp) = ui.allocate_exact_size(size, egui::Sense::click());

    let pressed = resp.is_pointer_button_down_on();
    let hovered = resp.hovered();
    let fill = if pressed {
        darken(
            if matches!(kind, BtnKind::Ghost) {
                p.raised2
            } else {
                base_fill
            },
            0.12,
        )
    } else if hovered {
        match kind {
            BtnKind::Ghost => p.raised2,
            BtnKind::Default => lighten(base_fill, 0.10),
            _ => lighten(base_fill, 0.08),
        }
    } else {
        base_fill
    };
    let stroke = if hovered && matches!(kind, BtnKind::Default | BtnKind::Ghost) {
        Stroke::new(1.0, p.accent)
    } else {
        base_stroke
    };
    let fg = if hovered && matches!(kind, BtnKind::Ghost) {
        p.txt
    } else {
        base_fg
    };

    let painter = ui.painter();
    painter.rect(rect, Rounding::same(8.0), fill, stroke);
    // Icon sits at the left padding; label follows after the gap.
    let icon_center = egui::pos2(rect.left() + pad_x + icon_w * 0.5, rect.center().y);
    let galley = painter.layout_no_wrap(label.to_owned(), f_sb(13.0), fg);
    let label_pos = egui::pos2(
        rect.left() + pad_x + icon_w + icon_gap,
        rect.center().y - galley.size().y * 0.5,
    );
    painter.galley(label_pos, galley, fg);
    if hovered {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }
    (resp, icon_center, fg)
}

/// Segmented control: a row of small buttons; returns the newly-clicked value.
/// `accent` lets the Molto2 use brand/amber while the rest use the accent.
pub fn segmented(
    ui: &mut egui::Ui,
    p: &Palette,
    options: &[&str],
    selected: &str,
    accent: Color32,
) -> Option<String> {
    let mut clicked = None;
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 6.0;
        for &opt in options {
            let on = opt == selected;
            let (fill, fg, stroke) = if on {
                (accent, p.accent_ink, Stroke::NONE)
            } else {
                (p.raised2, p.txt2, Stroke::new(1.0, p.line))
            };
            let hover_fill = if on { fill } else { lighten(fill, 0.10) };
            let hover_stroke = if on { stroke } else { Stroke::new(1.0, accent) };
            let r = ui.add(
                egui::Button::new(egui::RichText::new(opt).font(f_sb(12.0)).color(fg))
                    .fill(fill)
                    .stroke(stroke)
                    .rounding(Rounding::same(7.0)),
            );
            // Repaint the option's surface on hover so unselected segments read
            // as clickable (egui's fixed `.fill()` otherwise has no hover state).
            if r.hovered() {
                ui.painter()
                    .rect(r.rect, Rounding::same(7.0), hover_fill, hover_stroke);
                ui.painter().text(
                    r.rect.center(),
                    egui::Align2::CENTER_CENTER,
                    opt,
                    f_sb(12.0),
                    fg,
                );
                ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
            }
            if r.clicked() {
                clicked = Some(opt.to_string());
            }
        }
    });
    clicked
}

// ---- OATH countdown ring (partial arc, clockwise from 12 o'clock) ----
pub fn ring(ui: &mut egui::Ui, pct: f32, size: f32, color: Color32, track: Color32) {
    use std::f32::consts::{FRAC_PI_2, TAU};
    let (rect, _) = ui.allocate_exact_size(egui::vec2(size, size), egui::Sense::hover());
    let c = rect.center();
    let r = size / 2.0 - 1.5;
    let p = ui.painter();
    p.circle_stroke(c, r, Stroke::new(2.5, track));
    let pct = pct.clamp(0.0, 1.0);
    let n = (48.0 * pct).ceil().max(1.0) as usize;
    let pts: Vec<egui::Pos2> = (0..=n)
        .map(|i| {
            let t = pct * (i as f32 / n as f32);
            let a = -FRAC_PI_2 + TAU * t;
            c + r * egui::vec2(a.cos(), a.sin())
        })
        .collect();
    p.add(egui::Shape::line(pts, Stroke::new(2.5, color)));
}

/// Remaining seconds + fraction for a TOTP window. Use:
///   let (secs, pct) = totp_window(30);
///   ring(ui, pct, 20.0, code_color, p.line);
pub fn totp_window(period: u64) -> (u64, f32) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let rem = period - (now % period);
    (rem, rem as f32 / period as f32)
}

// --- UI scale ("Text size") --------------------------------------------------
//
// egui's global zoom factor scales the whole UI uniformly — fonts AND painted
// symbols — so one knob covers issue #42. We expose it as a "Text size" control
// and persist the chosen factor across launches.

/// Smallest allowed UI scale (80%).
pub const ZOOM_MIN: f32 = 0.8;
/// Largest allowed UI scale (200%).
pub const ZOOM_MAX: f32 = 2.0;
/// The default scale — 100%, i.e. the look existing users already see.
pub const ZOOM_DEFAULT: f32 = 1.0;

/// Clamp a zoom factor into the supported range, mapping any non-finite or
/// non-positive value (e.g. the `0.0` a `Default`-derived field starts at, or a
/// corrupt persisted value) back to the 100% default. Keeps `set_zoom_factor`
/// from ever being handed something egui would choke on.
pub fn clamp_zoom(factor: f32) -> f32 {
    if !factor.is_finite() || factor <= 0.0 {
        return ZOOM_DEFAULT;
    }
    factor.clamp(ZOOM_MIN, ZOOM_MAX)
}

#[cfg(test)]
mod zoom_tests {
    use super::*;

    #[test]
    fn default_field_value_normalizes_to_one() {
        // A `#[derive(Default)]` f32 field starts at 0.0; that must read back as
        // 100% so existing users see no change.
        assert_eq!(clamp_zoom(0.0), ZOOM_DEFAULT);
    }

    #[test]
    fn out_of_range_values_clamp() {
        assert_eq!(clamp_zoom(0.1), ZOOM_MIN);
        assert_eq!(clamp_zoom(5.0), ZOOM_MAX);
        assert_eq!(clamp_zoom(-1.0), ZOOM_DEFAULT);
    }

    #[test]
    fn non_finite_falls_back_to_default() {
        assert_eq!(clamp_zoom(f32::NAN), ZOOM_DEFAULT);
        assert_eq!(clamp_zoom(f32::INFINITY), ZOOM_DEFAULT);
    }

    #[test]
    fn in_range_values_pass_through() {
        assert_eq!(clamp_zoom(1.0), 1.0);
        assert_eq!(clamp_zoom(1.25), 1.25);
        assert_eq!(clamp_zoom(0.8), 0.8);
        assert_eq!(clamp_zoom(2.0), 2.0);
    }

    #[test]
    fn round_trips_through_string_like_storage() {
        // Mirrors save()/load(): format then parse back.
        for &f in &[0.8_f32, 1.0, 1.35, 2.0] {
            let s = f.to_string();
            let back: f32 = s.parse().unwrap();
            assert_eq!(clamp_zoom(back), f);
        }
    }

    #[test]
    fn save_then_load_preserves_chosen_factor() {
        // End-to-end mirror of the persistence path the GUI uses:
        //   save():  storage.set_string("zoom", clamp_zoom(self.zoom).to_string())
        //   load():  clamp_zoom(get_string("zoom").parse())
        // The chosen factor — not 1.0 — must survive the launch-to-launch trip.
        // Guards the reset-on-reopen regression: the value written must be the
        // user's pick, and reading it back must return that same pick clamped.
        fn save(chosen: f32) -> String {
            clamp_zoom(chosen).to_string()
        }
        fn load(stored: &str) -> f32 {
            clamp_zoom(stored.parse::<f32>().unwrap_or(ZOOM_DEFAULT))
        }
        for &chosen in &[0.8_f32, 1.0, 1.25, 1.5, 2.0] {
            assert_eq!(load(&save(chosen)), chosen);
        }
        // A chosen 1.5 must never silently persist as the 100% default.
        assert_ne!(load(&save(1.5)), ZOOM_DEFAULT);
        // Corrupt/missing storage still falls back to the default.
        assert_eq!(load("not-a-float"), ZOOM_DEFAULT);
    }
}
