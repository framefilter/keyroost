- **What keyroost knows a Feitian key's PIV to do goes by the PIV version
  it was measured at.** An ePass FIDO NFC Plus and a BioPass FIDO Pro are
  asked for their PIV application version, which `piv info` and the app
  show as Feitian writes it (`9166`, `4717`). A key of either product
  with an earlier version, or one whose version cannot be read, is still
  sent Feitian's commands; what was seen to work on the measured keys is
  then offered as unverified, not as known. Feitian says a later version
  of one product has the larger number, and that an update to a key can
  change what its PIV does. Checked on three keys with the command line.
  Contributed by @Snrat. ([#286])
