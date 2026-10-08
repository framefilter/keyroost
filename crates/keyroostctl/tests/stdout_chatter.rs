//! stdout carries the result (spec A): no prompt, progress, announce,
//! "wrote" line, note or warning reaches it. Scans the CLI's non-test
//! source for whole `println!`/`print!` statements whose text looks like chatter.

pub const SOURCES: &[(&str, &str)] = &[
    ("main.rs", include_str!("../src/main.rs")),
    ("overview.rs", include_str!("../src/overview.rs")),
];

const CHATTER: &[&str] = &[
    "touch the",
    "Touch the",
    "touch your",
    "Press the",
    "up-arrow button",
    "\"authenticated",
    "Authenticated",
    "Wrote ",
    "wrote ",
    "Generating ",
    "Loading ",
    "Importing ",
    "Power-cycling",
    "\\u{2026}",
    "\u{2026}",
    "remember to",
    "device serial",
    "device UTC",
    "Device UTC",
    "programming slots",
    "READ_CONFIG returned",
    "warning:",
    "WARNING:",
    "note:",
    "Note:",
    "Export with:",
    "use the id with",
];

/// Results that legitimately contain one of the words above.
const ALLOWED: &[&str] = &[
    "Fingerprint protection enabled", // fingerprint enable ack: tells the user what changed
    "wiped (warning:",                // factory-reset step line: the step's result
    "Wrote a new CHUID",              // piv set-chuid ack: the card write is the result
    // `doctor` / `list` report a bootloader-mode device inline, under the
    // section it belongs to: the report is the result.
    "re-plug it",
];

/// Every stdout print statement in `src` before the first test module:
/// (1-based line, the statement text up to its closing `);`).
pub fn stdout_prints(src: &str) -> Vec<(usize, String)> {
    let code = src.split("#[cfg(test)]").next().unwrap();
    let lines: Vec<&str> = code.lines().collect();
    let mut out = Vec::new();
    for (i, l) in lines.iter().enumerate() {
        if !(l.contains("println!(") || l.contains("print!(")) || l.contains("eprint") {
            continue;
        }
        let mut text = String::new();
        for next in &lines[i..] {
            text.push_str(next);
            text.push(' ');
            if next.trim_end().ends_with(");") || next.trim_end().ends_with("),") {
                break;
            }
        }
        out.push((i + 1, text));
    }
    out
}

#[test]
fn scanner_reads_the_whole_statement() {
    let src = "fn f() {\n    println!(\n        \"{}\",\n        x,\n        \"touch the key\"\n    );\n}\n";
    let found = stdout_prints(src);
    assert_eq!(found.len(), 1);
    assert!(found[0].1.contains("touch the key"));
}

#[test]
fn no_chatter_on_stdout() {
    let mut bad = Vec::new();
    for (file, src) in SOURCES {
        for (line, text) in stdout_prints(src) {
            if ALLOWED.iter().any(|a| text.contains(a)) {
                continue;
            }
            if let Some(w) = CHATTER.iter().find(|w| text.contains(*w)) {
                bad.push(format!("{file}:{line}: {w:?}"));
            }
        }
    }
    assert!(bad.is_empty(), "stdout chatter:\n{}", bad.join("\n"));
}

#[test]
fn one_warning_and_note_style() {
    for (file, src) in SOURCES {
        let code = src.split("#[cfg(test)]").next().unwrap();
        for (i, l) in code.lines().enumerate() {
            for bad in [
                "\"WARNING:",
                "\"Note:",
                "\"NOTE:",
                "\"Warning:",
                "profile #",
            ] {
                assert!(!l.contains(bad), "{file}:{}: {bad}: {}", i + 1, l.trim());
            }
        }
    }
}
