//! Calendar-date model and typed expiry entry for OpenPGP key creation and
//! "Change expiry date…".

// The calendar helpers and `for_existing` wait for the calendar popup and
// the change-expiry dialog.
#![allow(dead_code)]

use super::theme::{f_reg, Palette};
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

    /// Changing an existing key: open on its current expiry date (or today
    /// when it has none), with "Pick a date…" selected.
    pub fn for_existing(current: Option<Date>, today: Date) -> Self {
        let d = current.unwrap_or(today);
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
                let d = Date::parse(&self.text).ok_or("Type a date as YYYY-MM-DD.")?;
                // Valid through the whole of the chosen day, so today is fine.
                if today.is_after(&d) {
                    return Err("That date is in the past.");
                }
                if d.y > 2105 {
                    return Err("Pick a date before 2106.");
                }
                Ok(Expiry::Date {
                    y: d.y,
                    m: d.m,
                    d: d.d,
                })
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
            ui.add(
                egui::TextEdit::singleline(&mut input.text)
                    .hint_text("YYYY-MM-DD")
                    .desired_width(110.0)
                    .font(f_reg(13.0)),
            );
            // Task 13 adds `calendar_button(ui, p, input, today)` here.
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
            };
            ui.label(egui::RichText::new(line).font(f_reg(12.0)).color(p.txt2));
        }
    }
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
        assert_eq!(e.text, "2026-10-17");
        let e = ExpiryInput::for_existing(Some(dt(2028, 1, 2)), today);
        assert_eq!(e.text, "2028-01-02");
        assert_eq!(e.month, dt(2028, 1, 1));
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
        assert_eq!(i.resolve(today), Err("Type a date as YYYY-MM-DD."));
        i.text = "2026-10-17".into();
        assert_eq!(
            i.resolve(today),
            Ok(Expiry::Date {
                y: 2026,
                m: 10,
                d: 17
            })
        );
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
