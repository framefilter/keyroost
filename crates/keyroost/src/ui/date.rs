//! Calendar-date model and typed expiry entry for OpenPGP key creation and
//! "Change expiry date…".

use super::theme::{button, f_reg, f_sb, BtnKind, Palette};
use keyroost_pgpkey::cert::{civil_from_days, days_from_civil, Expiry};

const MONTHS: [&str; 12] = [
    "January",
    "February",
    "March",
    "April",
    "May",
    "June",
    "July",
    "August",
    "September",
    "October",
    "November",
    "December",
];

/// A proleptic Gregorian calendar date (UTC, as the key's expiry is).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Date {
    pub y: i32,
    pub m: u8,
    pub d: u8,
}

impl Date {
    /// Today's date from the computer's clock.
    pub fn today_utc() -> Date {
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let (y, m, d) = civil_from_days(i64::try_from(secs / 86_400).unwrap_or(0));
        Date { y, m, d }
    }

    /// A `(year, month, day)` as the key library gives it
    /// (`cert::current_expiry`).
    pub fn from_civil((y, m, d): (i32, u8, u8)) -> Date {
        Date { y, m, d }
    }

    /// Strict `YYYY-MM-DD`; `None` for anything that is not a real date.
    pub fn parse(s: &str) -> Option<Date> {
        let parts: Vec<&str> = s.trim().split('-').collect();
        let [ys, ms, ds] = parts[..] else {
            return None;
        };
        if ys.len() != 4 || ms.len() != 2 || ds.len() != 2 {
            return None;
        }
        if ![ys, ms, ds]
            .iter()
            .all(|p| p.bytes().all(|b| b.is_ascii_digit()))
        {
            return None;
        }
        let (y, m, d): (i32, u8, u8) = (ys.parse().ok()?, ms.parse().ok()?, ds.parse().ok()?);
        if !(1..=12).contains(&m) || d == 0 || d > Self::days_in_month(y, m) {
            return None;
        }
        Some(Date { y, m, d })
    }

    pub fn iso(&self) -> String {
        format!("{:04}-{:02}-{:02}", self.y, self.m, self.d)
    }

    /// "16 October 2029".
    pub fn long(&self) -> String {
        format!(
            "{} {} {}",
            self.d,
            MONTHS[usize::from(self.m.clamp(1, 12)) - 1],
            self.y
        )
    }

    /// Same day `n` years on; Feb 29 falls back to Feb 28 in a common year.
    /// The day after this one.
    pub fn next_day(&self) -> Date {
        Date::from_civil(civil_from_days(days_from_civil(self.y, self.m, self.d) + 1))
    }

    pub fn add_years(&self, n: i32) -> Date {
        let y = self.y + n;
        Date {
            y,
            m: self.m,
            d: self.d.min(Self::days_in_month(y, self.m)),
        }
    }

    pub fn days_in_month(y: i32, m: u8) -> u8 {
        match m {
            1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
            4 | 6 | 9 | 11 => 30,
            _ if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 => 29,
            _ => 28,
        }
    }

    /// 0 = Monday … 6 = Sunday.
    pub fn weekday(&self) -> u8 {
        // 1970-01-01 (day 0) was a Thursday.
        (days_from_civil(self.y, self.m, self.d) + 3).rem_euclid(7) as u8
    }

    /// The first of the following month.
    pub fn next_month(&self) -> Date {
        if self.m == 12 {
            Date {
                y: self.y + 1,
                m: 1,
                d: 1,
            }
        } else {
            Date {
                y: self.y,
                m: self.m + 1,
                d: 1,
            }
        }
    }

    /// The first of the previous month.
    pub fn prev_month(&self) -> Date {
        if self.m == 1 {
            Date {
                y: self.y - 1,
                m: 12,
                d: 1,
            }
        } else {
            Date {
                y: self.y,
                m: self.m - 1,
                d: 1,
            }
        }
    }

    fn day_number(&self) -> i64 {
        days_from_civil(self.y, self.m, self.d)
    }

    /// "October 2026".
    pub fn month_title(&self) -> String {
        format!(
            "{} {}",
            MONTHS[usize::from(self.m.clamp(1, 12)) - 1],
            self.y
        )
    }

    pub fn is_after(&self, o: &Date) -> bool {
        (self.y, self.m, self.d) > (o.y, o.m, o.d)
    }

    fn first_of_month(&self) -> Date {
        Date {
            y: self.y,
            m: self.m,
            d: 1,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpiryChoice {
    Never,
    Years(u8),
    /// "Pick a date…": the typed date in [`ExpiryInput::text`].
    Date,
}

/// The state behind one expiry dropdown + date field.
#[derive(Debug, Clone)]
pub struct ExpiryInput {
    pub choice: ExpiryChoice,
    pub text: String,
    pub calendar_open: bool,
    /// The month the calendar popup shows (first of the month).
    pub month: Date,
}

impl ExpiryInput {
    /// A new key: three years, with the date field ready at that date.
    pub fn for_new(today: Date) -> Self {
        let d = today.add_years(3);
        ExpiryInput {
            choice: ExpiryChoice::Years(3),
            text: d.iso(),
            calendar_open: false,
            month: d.first_of_month(),
        }
    }

    /// Changing an existing key: open on its current expiry date (or
    /// tomorrow, the first date it can take, when it has none), with
    /// "Pick a date…" selected.
    pub fn for_existing(current: Option<Date>, today: Date) -> Self {
        let d = current.unwrap_or_else(|| today.next_day());
        ExpiryInput {
            choice: ExpiryChoice::Date,
            text: d.iso(),
            calendar_open: false,
            month: d.first_of_month(),
        }
    }

    pub fn resolve(&self, today: Date) -> Result<Expiry, &'static str> {
        match self.choice {
            ExpiryChoice::Never => Ok(Expiry::Never),
            ExpiryChoice::Years(n) => Ok(Expiry::Years(n)),
            ExpiryChoice::Date => {
                // The CLI's check and wording (`--expires`).
                let e = Expiry::parse_date(&self.text)?;
                let Expiry::Date { y, m, d } = e else {
                    return Ok(e);
                };
                // The key expires at midday UTC that day, so today is too soon.
                let day = Date { y, m, d };
                if today.is_after(&day) {
                    return Err("That date is in the past.");
                }
                if day == today {
                    return Err("Pick a date after today.");
                }
                Ok(e)
            }
        }
    }

    fn choice_label(&self) -> &'static str {
        match self.choice {
            ExpiryChoice::Never => "Never",
            ExpiryChoice::Years(1) => "1 year",
            ExpiryChoice::Years(2) => "2 years",
            ExpiryChoice::Years(3) => "3 years",
            ExpiryChoice::Years(5) => "5 years",
            ExpiryChoice::Years(_) => "Years",
            ExpiryChoice::Date => "Pick a date\u{2026}",
        }
    }
}

/// The expiry dropdown, the date field when "Pick a date…" is chosen, and a
/// one-line result underneath.
pub fn expiry_row(ui: &mut egui::Ui, p: &Palette, input: &mut ExpiryInput, today: Date) {
    ui.horizontal_wrapped(|ui| {
        egui::ComboBox::from_id_salt("expiry_choice")
            .truncate()
            .selected_text(input.choice_label())
            .show_ui(ui, |ui| {
                ui.selectable_value(&mut input.choice, ExpiryChoice::Never, "Never");
                for (n, label) in [
                    (1, "1 year"),
                    (2, "2 years"),
                    (3, "3 years"),
                    (5, "5 years"),
                ] {
                    ui.selectable_value(&mut input.choice, ExpiryChoice::Years(n), label);
                }
                ui.selectable_value(&mut input.choice, ExpiryChoice::Date, "Pick a date\u{2026}");
            });
        if input.choice == ExpiryChoice::Date {
            let edit = ui.add(
                egui::TextEdit::singleline(&mut input.text)
                    .hint_text("YYYY-MM-DD")
                    .desired_width(110.0)
                    .font(f_reg(13.0)),
            );
            // Typing a real date moves the calendar to that month.
            if edit.changed() {
                if let Some(d) = Date::parse(&input.text) {
                    input.month = d.first_of_month();
                }
            }
            calendar_button(ui, p, input, today);
        } else {
            input.calendar_open = false;
            set_calendar_showing(ui.ctx(), false);
        }
    });
    match input.resolve(today) {
        Err(e) => {
            ui.label(egui::RichText::new(e).font(f_reg(12.0)).color(p.err));
        }
        Ok(exp) => {
            let line = match exp {
                Expiry::Never => "Never expires".to_string(),
                Expiry::Years(n) => format!("Expires on {}", today.add_years(i32::from(n)).long()),
                Expiry::Date { y, m, d } => format!("Expires on {}", Date { y, m, d }.long()),
                // A choice added later: its end moment, as a date.
                other => {
                    let from = days_from_civil(today.y, today.m, today.d) * 86_400;
                    match u32::try_from(from)
                        .ok()
                        .and_then(|f| other.end_time(f).ok())
                    {
                        Some(Some(end)) => {
                            let (y, m, d) = civil_from_days((i64::from(end) - 1) / 86_400);
                            format!("Expires on {}", Date { y, m, d }.long())
                        }
                        _ => "Never expires".to_string(),
                    }
                }
            };
            ui.label(egui::RichText::new(line).font(f_reg(12.0)).color(p.txt2));
        }
    }
}

/// The 42 days (six Monday-first weeks) a month's calendar page shows,
/// beginning on the Monday on or before the 1st.
pub fn month_grid(month: Date) -> [Date; 42] {
    let first = month.first_of_month();
    let start = first.day_number() - i64::from(first.weekday());
    std::array::from_fn(|i| {
        let (y, m, d) = civil_from_days(start + i as i64);
        Date { y, m, d }
    })
}

fn showing_id() -> egui::Id {
    egui::Id::new("expiry_calendar_showing")
}

fn set_calendar_showing(ctx: &egui::Context, on: bool) {
    let stamp = on.then(|| ctx.cumulative_pass_nr());
    ctx.data_mut(|d| d.insert_temp(showing_id(), stamp));
}

/// A stamp counts when it was written this pass or the one before, so a
/// calendar that stops being drawn stops counting by itself.
fn stamp_is_fresh(stamp: Option<u64>, now: u64) -> bool {
    stamp.is_some_and(|s| s.saturating_add(1) >= now)
}

/// Whether a calendar popup is open. The dialog around it uses this to
/// leave Esc to the calendar instead of closing itself too.
pub fn calendar_showing(ctx: &egui::Context) -> bool {
    let stamp = ctx.data(|d| d.get_temp::<Option<u64>>(showing_id()));
    stamp_is_fresh(stamp.flatten(), ctx.cumulative_pass_nr())
}

/// A "Calendar" button and, while open, a month popup under it. Picking a
/// day writes it into `input.text`; today and earlier days can't be picked.
pub fn calendar_button(ui: &mut egui::Ui, p: &Palette, input: &mut ExpiryInput, today: Date) {
    let btn = button(ui, p, BtnKind::Default, "Calendar");
    if btn.clicked() {
        input.calendar_open = !input.calendar_open;
        if input.calendar_open {
            if let Some(d) = Date::parse(&input.text) {
                input.month = d.first_of_month();
            }
        }
    }
    if !input.calendar_open {
        set_calendar_showing(ui.ctx(), false);
        return;
    }
    let selected = Date::parse(&input.text);
    let mut open = input.calendar_open;
    let mut picked = None;
    let mut month = input.month;
    let max_bottom = ui.ctx().content_rect().bottom();
    egui::Popup::from_response(&btn)
        .open_bool(&mut open)
        .close_behavior(egui::PopupCloseBehavior::CloseOnClickOutside)
        .frame(
            egui::Frame::popup(ui.style())
                .fill(p.pop)
                .stroke(egui::Stroke::new(1.0, p.line)),
        )
        .show(|ui| {
            // Keep the page on screen: at a large text size in a short
            // window it scrolls instead of running off the bottom.
            let max_h = (max_bottom - ui.next_widget_position().y - 12.0).max(160.0);
            ui.set_max_height(max_h);
            egui::ScrollArea::vertical()
                .max_height(max_h)
                .show(ui, |ui| {
                    let w = ui
                        .painter()
                        .layout_no_wrap("00".into(), f_reg(13.0), p.txt)
                        .size();
                    let cell = egui::vec2(w.x + 12.0, w.y + 4.0);
                    ui.spacing_mut().item_spacing = egui::vec2(2.0, 2.0);
                    ui.horizontal(|ui| {
                        if ui
                            .add(egui::Button::new(
                                egui::RichText::new("\u{2039}").font(f_sb(18.0)),
                            ))
                            .clicked()
                        {
                            month = month.prev_month();
                        }
                        let title = month.month_title();
                        let room = cell.x * 7.0 + 12.0 - 2.0 * (cell.y + 6.0);
                        ui.allocate_ui_with_layout(
                            egui::vec2(room.max(60.0), cell.y),
                            egui::Layout::centered_and_justified(egui::Direction::LeftToRight),
                            |ui| {
                                ui.label(egui::RichText::new(title).font(f_sb(13.0)).color(p.txt));
                            },
                        );
                        if ui
                            .add(egui::Button::new(
                                egui::RichText::new("\u{203A}").font(f_sb(18.0)),
                            ))
                            .clicked()
                        {
                            month = month.next_month();
                        }
                    });
                    ui.add_space(2.0);
                    egui::Grid::new("calendar_grid")
                        .spacing(egui::vec2(2.0, 2.0))
                        .show(ui, |ui| {
                            for name in ["Mo", "Tu", "We", "Th", "Fr", "Sa", "Su"] {
                                let (r, _) = ui.allocate_exact_size(cell, egui::Sense::hover());
                                ui.painter().text(
                                    r.center(),
                                    egui::Align2::CENTER_CENTER,
                                    name,
                                    f_reg(12.0),
                                    p.txt3,
                                );
                            }
                            ui.end_row();
                            for (i, day) in month_grid(month).iter().enumerate() {
                                let in_month = day.m == month.m;
                                let past = !day.is_after(&today);
                                let sense = if past {
                                    egui::Sense::hover()
                                } else {
                                    egui::Sense::click()
                                };
                                let (r, resp) = ui.allocate_exact_size(cell, sense);
                                let is_sel = selected == Some(*day);
                                if is_sel {
                                    ui.painter().rect_filled(r, 4.0, p.accent);
                                } else if resp.hovered() && !past {
                                    ui.painter().rect_filled(r, 4.0, p.accent_soft());
                                }
                                if *day == today {
                                    ui.painter().rect_stroke(
                                        r,
                                        4.0,
                                        egui::Stroke::new(1.5, p.accent),
                                        egui::StrokeKind::Inside,
                                    );
                                }
                                let col = if is_sel {
                                    p.accent_ink
                                } else if past || !in_month {
                                    p.txt3
                                } else {
                                    p.txt
                                };
                                ui.painter().text(
                                    r.center(),
                                    egui::Align2::CENTER_CENTER,
                                    day.d.to_string(),
                                    f_reg(13.0),
                                    col,
                                );
                                if !past && resp.clicked() {
                                    picked = Some(*day);
                                }
                                if i % 7 == 6 {
                                    ui.end_row();
                                }
                            }
                        });
                });
        });
    input.month = month;
    input.calendar_open = open;
    if let Some(d) = picked {
        input.text = d.iso();
        input.month = d.first_of_month();
        input.calendar_open = false;
    }
    set_calendar_showing(ui.ctx(), input.calendar_open);
}

#[cfg(test)]
mod tests {
    use super::*;
    fn dt(y: i32, m: u8, d: u8) -> Date {
        Date { y, m, d }
    }

    #[test]
    fn leap_years() {
        assert!(Date::parse("2024-02-29").is_some());
        assert!(Date::parse("2000-02-29").is_some());
        assert!(Date::parse("2100-02-29").is_none());
        assert!(Date::parse("2026-02-29").is_none());
        assert!(Date::parse("2029-13-01").is_none());
        assert!(Date::parse("2029-01-00").is_none());
        assert!(Date::parse("soon").is_none());
        assert_eq!(Date::parse(" 2029-10-16 "), Some(dt(2029, 10, 16)));
    }

    #[test]
    fn formatting_and_weekday() {
        assert_eq!(dt(2029, 10, 16).iso(), "2029-10-16");
        assert_eq!(dt(2029, 3, 5).long(), "5 March 2029");
        assert_eq!(dt(2029, 10, 16).long(), "16 October 2029");
        assert_eq!(dt(2026, 10, 16).weekday(), 4);
        assert_eq!(dt(1970, 1, 1).weekday(), 3);
    }

    #[test]
    fn year_and_month_arithmetic() {
        assert_eq!(dt(2024, 2, 29).add_years(1), dt(2025, 2, 28));
        assert_eq!(dt(2024, 2, 29).add_years(4), dt(2028, 2, 29));
        assert_eq!(dt(2026, 12, 15).next_month(), dt(2027, 1, 1));
        assert_eq!(dt(2026, 1, 15).prev_month(), dt(2025, 12, 1));
        assert!(dt(2026, 10, 17).is_after(&dt(2026, 10, 16)));
        assert!(!dt(2026, 10, 16).is_after(&dt(2026, 10, 16)));
    }

    #[test]
    fn month_grid_is_six_monday_first_weeks() {
        let g = month_grid(dt(2026, 10, 1));
        assert_eq!(g.len(), 42);
        assert_eq!(g[0], dt(2026, 9, 28));
        assert_eq!(g[0].weekday(), 0);
        assert!(g.contains(&dt(2026, 10, 31)));
        assert!(g
            .iter()
            .enumerate()
            .all(|(i, d)| usize::from(d.weekday()) == i % 7));
        assert_eq!(g[41], dt(2026, 11, 8));
        // A month starting on Monday begins its own grid.
        assert_eq!(month_grid(dt(2026, 6, 15))[0], dt(2026, 6, 1));
    }

    #[test]
    fn calendar_stamp_expires() {
        assert!(stamp_is_fresh(Some(10), 10));
        assert!(stamp_is_fresh(Some(10), 11));
        assert!(!stamp_is_fresh(Some(10), 12));
        assert!(!stamp_is_fresh(None, 10));
    }

    #[test]
    fn today_is_plausible() {
        assert!(Date::today_utc().y >= 2026);
    }

    #[test]
    fn new_and_existing_defaults() {
        let today = dt(2026, 10, 17);
        let n = ExpiryInput::for_new(today);
        assert_eq!(n.choice, ExpiryChoice::Years(3));
        assert_eq!(n.text, "2029-10-17");
        let e = ExpiryInput::for_existing(None, today);
        assert_eq!(e.choice, ExpiryChoice::Date);
        assert_eq!(e.text, "2026-10-18");
        assert_eq!(dt(2026, 12, 31).next_day(), dt(2027, 1, 1));
        let e = ExpiryInput::for_existing(Some(dt(2028, 1, 2)), today);
        assert_eq!(e.text, "2028-01-02");
        assert_eq!(e.month, dt(2028, 1, 1));
    }

    #[test]
    fn change_dialog_opens_on_the_keys_own_expiry() {
        let today = dt(2026, 10, 17);
        let e = ExpiryInput::for_existing(Some(Date::from_civil((2027, 10, 8))), today);
        assert_eq!(e.choice, ExpiryChoice::Date);
        assert_eq!(e.text, "2027-10-08");
        assert_eq!(
            e.resolve(today),
            Ok(Expiry::Date {
                y: 2027,
                m: 10,
                d: 8
            })
        );
    }

    #[test]
    fn resolve_choices_and_errors() {
        let today = dt(2026, 10, 17);
        let mut i = ExpiryInput::for_new(today);
        assert_eq!(i.resolve(today), Ok(Expiry::Years(3)));
        i.choice = ExpiryChoice::Never;
        assert_eq!(i.resolve(today), Ok(Expiry::Never));
        i.choice = ExpiryChoice::Date;
        i.text = "2029-10-16".into();
        assert_eq!(
            i.resolve(today),
            Ok(Expiry::Date {
                y: 2029,
                m: 10,
                d: 16
            })
        );
        i.text = "2029-02-30".into();
        assert_eq!(i.resolve(today), Err("That date does not exist."));
        i.text = "2029-2-3".into();
        assert_eq!(i.resolve(today), Err("Enter the date as YYYY-MM-DD."));
        i.text = "2026-10-18".into();
        assert_eq!(
            i.resolve(today),
            Ok(Expiry::Date {
                y: 2026,
                m: 10,
                d: 18
            })
        );
        i.text = "2026-10-17".into();
        assert_eq!(i.resolve(today), Err("Pick a date after today."));
        i.text = "2026-10-16".into();
        assert_eq!(i.resolve(today), Err("That date is in the past."));
        i.text = "2105-12-31".into();
        assert!(i.resolve(today).is_ok());
        i.text = "2106-01-01".into();
        assert_eq!(i.resolve(today), Err("Pick a date before 2106."));
        i.text = "2020-01-01".into();
        assert_eq!(i.resolve(today), Err("That date is in the past."));
    }
}
