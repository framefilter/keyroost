- **`openpgp info` shows a Token2 key's full serial.** The OpenPGP card
  data holds only a shortened serial, so keyroost now reads the full one
  from the key's OTP applet, the way `piv info` has since 0.12.0 (built on
  @episource's PIV work). This covers the CLI, its JSON `serial` field and
  the GUI's OpenPGP view. ([#125])
