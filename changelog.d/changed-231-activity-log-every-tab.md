- **The activity log covers every tab.** Changes and their errors in the
  Authenticator, On-device OTP, FIDO2 and OpenPGP tabs, a FIDO2 reset on
  its own, and an import that wrote nothing now write a line, as the PIV
  and Molto2 tabs' changes already did. A change whose re-read afterwards
  fails is still logged as made. Lines name no Authenticator account, and
  show your home folder as `~`. A failure an automatic refresh keeps
  hitting is logged once. With APDU trace on, a read or refresh that
  writes no line of its own, such as reading Authenticator codes, gets one
  named after it, so its traffic is never dropped; the checkbox explains
  this when you hover it. `fido config` and `fido fingerprint` say "this
  key does not support" like the other settings commands. ([#231])
