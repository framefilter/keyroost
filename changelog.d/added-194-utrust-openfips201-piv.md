- **PIV on an Identiv/Hirsch uTrust FIDO2 key with firmware 3.33.** A
  uTrust key whose PIV application names itself OpenFIPS201 is now told
  apart from the uTrust key whose application carries no name, and has
  rows of its own from application version 1.10.6 up. keyroost offers
  it the key types it holds (RSA-2048, P-256 and P-384), knows its
  default management key, so "use the default management key" works,
  and changes its management key with the card's own command
  (`piv mgmt-key change` and the app's change; the key is AES-128).
  Before, it showed as a generic OpenFIPS201 card with every key type
  unverified, no default key and no way to change the key. PIV reset
  stays off for it. The key with firmware 3.30 in [#194] runs the other
  application and nothing changes for it. Checked on a uTrust FIDO2 NFC
  with the command line. Contributed by @Snrat. ([#194])
