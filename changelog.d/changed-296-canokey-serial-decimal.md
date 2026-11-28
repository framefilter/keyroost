- **A CanoKey's serial is shown in decimal,** as CanoKey's own tools show
  it, in `list`, `fido info` and the app. `openpgp info` adds the hex
  digits GnuPG shows after it (`439041101 (0x1A2B3C4D)`), and its `--json`
  gives the decimal one. A name set for a CanoKey earlier still applies.
  A CanoKey whose serial was never written (all zeros or all `F`) is
  treated as having no serial. The overview now shortens a serial only
  past ten characters. ([#296])
