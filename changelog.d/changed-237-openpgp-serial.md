- **`openpgp info` shows a YubiKey's or Nitrokey's serial as the key
  names it.** It read the card's four serial bytes as one number:
  `931162176 (0x37806840)` for YubiKey 37806840, `1114124023
  (0x42682EF7)` for Nitrokey 3 42682EF7. It now shows those bytes the way
  GnuPG does, which is the key's own serial; the app's OpenPGP tab, the
  reset message and `--json`'s `serial` field (a string, as before) follow.
  A Token2 key still shows its full serial when its OTP applet answers.
  ([#237])
