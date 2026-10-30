- **`piv test` works on a slot with a key but no certificate.** It tested
  only against the slot's certificate, so an X25519 key (which can't sign
  one) or a freshly generated key couldn't be tested at all. Such a slot is
  now tested against the public key the card reports for it (GET METADATA,
  e.g. a YubiKey 5.3 or later), and the result says no certificate was
  part of the test;
  `--json` adds `cert_tested`. Slots with a certificate are tested as
  before. The app's Test button follows. ([#243])
