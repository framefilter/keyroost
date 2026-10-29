- **The activity log covers every tab.** Adding, deleting and resetting in
  the Authenticator and On-device OTP tabs, and their errors, now write a
  line, as the other tabs' changes already did (account names stay out of
  it). With APDU trace on, a read or refresh that writes no line of its
  own, such as reading Authenticator codes, gets one named after it, so
  its traffic is never dropped; the checkbox explains this when you hover
  it. `fido config` and `fido fingerprint` say "this key does not support"
  like the other settings commands. ([#231])
