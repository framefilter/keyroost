- **Import authenticator codes into any key that stores them.** `oath
  import` adds every code in an Aegis (plain or encrypted), 2FAS,
  `otpauth://` list or QR export to a YubiKey, Solo 2 or Nitrokey 3, and
  `otp import` to a Token2 key's OTP storage. In the GUI, drop the file on
  the window or click "Import file…" in the Authenticator, On-device OTP or
  Molto2 view; the "Import authenticator codes" dialog works for every key
  that stores codes. keyroost reads the key first and previews each entry:
  a code whose name is already on the key is skipped (`--replace`
  replaces it), and one the key can't store is listed with the reason.
  `--dry-run` writes nothing. It asks once, writes one code at a time, and
  stops at the first error with a report of what was added. ([#170])
