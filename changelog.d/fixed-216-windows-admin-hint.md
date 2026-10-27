- **Without administrator rights on Windows, "no key" errors say why.**
  `fido info` and `otp --transport hid` said no key was connected when a
  FIDO key was plugged in. Windows only lets a program running as
  administrator open a key's FIDO USB side, and the error now says so, as
  `list` already did. ([#216])
