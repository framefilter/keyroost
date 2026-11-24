- **A failed random source is reported, not a crash.** If the operating
  system's random number source fails, FIDO2 PIN operations, the on-key
  name and Token2 OTP session setup now stop with "the system's random
  number source failed" instead of ending the program, and nothing is sent
  to the key. ([#283])
