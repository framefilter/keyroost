- **macOS fixes from a macOS test.** `keyroostctl doctor` no longer reports
  every FIDO key as "No such file or directory" on macOS and Windows: it
  now opens each key the same way `fido info` does. Scanning a QR code from
  the screen on macOS covers every display instead of only the main one,
  and the screenshots go in a private temporary folder that is always
  removed afterwards. Smart-card readers plugged in after the app started
  are now noticed where the system doesn't announce new readers (as on
  macOS). The macOS builds now state their minimum: macOS 11 (Big Sur) or
  newer. The PIV page records that macOS's built-in PIV support read a
  compressed certificate. ([#188])
