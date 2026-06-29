# keyroost-winwebauthn

Windows-only helper for keyroost's **non-admin FIDO2 tab**. Reviewed skeleton —
the Windows code can't be compiled or run off-Windows; build and verify it there.

## Scope (deliberately small)

keyroost needs admin to manage a FIDO key directly on Windows (the FIDO-HID
interface is gated since Win10 1903). When keyroost is not elevated, this crate
provides just enough for an informational tab:

- `detect_fido_keys()` / `fido_key_present()` — detect a FIDO key WITHOUT admin,
  via the HID usage page `0xF1D0` (no FIDO interface is opened).
- `open_windows_security_key_settings()` — open Windows' built-in Settings >
  Accounts > Sign-in options > Security Key page, which does PIN / reset /
  biometrics WITHOUT admin (Settings is itself the privileged component).

That's all. No passkey enumeration, no PIN/reset via API. The `webauthn.dll` API
was investigated and proved a dead end for **external** keys: its credential
list/delete only cover Windows Hello / TPM credentials, and it has no PIN or
reset function at all. So the design is: detect + inform + link out to Windows.

## Intended tab (non-admin Windows, FIDO key detected)

> Managing this security key's FIDO2 settings (PIN, passkeys, reset,
> fingerprints) requires administrator rights, or you can use Windows' built-in
> security-key management.

with a single button: **Open Windows security-key settings** →
`open_windows_security_key_settings()`.

## Verify on Windows

```
cargo run -p keyroost-winwebauthn --example probe
cargo run -p keyroost-winwebauthn --example probe -- --open-settings
```

Expect the probe to list your Token2 key, and `--open-settings` to open the
Windows security-key page. Risky FFI spots are marked `VERIFY:` in `src/sys.rs`
(the SetupAPI detail `cbSize`, the HID open flags, the usage-page read).

## Status

- Non-Windows (inert) path: compiles clean.
- Windows path: NOT compiled in CI (no Windows toolchain). Reviewed against docs.
