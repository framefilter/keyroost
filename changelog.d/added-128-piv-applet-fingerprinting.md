- **PIV applet fingerprinting.** keyroost now identifies which PIV
  implementation a card runs (YubiKey, Token2, Nitrokey, uTrust, HID
  Crescendo, OpenFIPS201 and others) from its ATR, SELECT response, and a few
  cheap AID probes, and uses that to gate vendor extensions precisely: MOVE
  and DELETE KEY are shown as supported only on a card fingerprinted as a
  YubiKey new enough for them, and dimmed with a reason elsewhere rather than
  hidden. Token2's BCD-coded PIV and OpenPGP serials are decoded, and serials
  wider than 64 bits (a Nitrokey's admin serial) display as hex. Contributed
  by @episource. ([#128])
- **`piv status --json` reports `serial` as a string.** A serial can now be
  up to 128 bits, and a bare JSON number past 2^53 loses precision in most
  consumers, so the field is a decimal string within 64 bits and `0x`-hex
  beyond — matching the text output. It was a number in 0.9.0. ([#128])
