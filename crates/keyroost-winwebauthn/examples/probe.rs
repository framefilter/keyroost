//! Manual probe for the slimmed `keyroost-winwebauthn`. Run WITHOUT admin, with
//! a FIDO key inserted:
//!
//!   cargo run -p keyroost-winwebauthn --example probe
//!   cargo run -p keyroost-winwebauthn --example probe -- --open-settings
//!
//! What to look for:
//!   * "FIDO key(s) detected" lists your Token2 key (usage page 0xF1D0)
//!   * with --open-settings, the Windows security-key page opens
//!
//! Read-only except for --open-settings (which just launches a Settings page).

use keyroost_winwebauthn as w;

fn main() {
    println!("keyroost-winwebauthn probe\n");

    let debug = std::env::args().any(|a| a == "--debug");
    let keys = if debug {
        let (keys, log) = w::detect_fido_keys_verbose();
        println!("--- HID enumeration ---");
        for line in &log {
            println!("{line}");
        }
        println!("-----------------------\n");
        keys
    } else {
        w::detect_fido_keys()
    };

    if keys.is_empty() {
        println!("no FIDO key detected (no HID device with usage page 0xF1D0)");
        if !debug {
            println!("re-run with `--debug` to list every HID device the scan saw.");
        }
    } else {
        println!("{} FIDO key(s) detected (usage page 0xF1D0):", keys.len());
        for (i, k) in keys.iter().enumerate() {
            let vid = k.vendor_id.map(|v| format!("{v:04X}")).unwrap_or_default();
            let pid = k.product_id.map(|v| format!("{v:04X}")).unwrap_or_default();
            println!(
                "  [{i}] {}  VID:{vid} PID:{pid}",
                k.product.as_deref().unwrap_or("(no product string)")
            );
        }
    }
    println!();

    if std::env::args().any(|a| a == "--open-settings") {
        println!("opening Windows security-key settings...");
        match w::open_windows_security_key_settings() {
            Ok(()) => println!("  launched (a Settings window should appear)."),
            Err(e) => println!("  failed: {e}"),
        }
    } else {
        println!("re-run with `--open-settings` to open the Windows security-key page.");
    }
}
