- **Files saved by Windows tools import.** An Aegis or 2FAS export or an
  otpauth:// list that starts with a byte-order mark (as Windows PowerShell
  5.1's `Out-File -Encoding utf8` and some editors write) was refused, or
  lost its first account; UTF-16 text (what PowerShell 5.1's `>` writes)
  wasn't read at all. Both now import, in the app and with
  `keyroostctl … import`. ([#205])
