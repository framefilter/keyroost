- **A Token2 PIN+ R3.4 shows the serial printed on it on Windows.** Its
  row, the app header and `list` showed an 8-digit number taken from its
  OpenPGP applet, because Windows doesn't let keyroost reach the key's
  FIDO side through its reader. keyroost now reads the full serial from
  the key's OTP applet; names saved under the old number still apply.
  ([#249])
