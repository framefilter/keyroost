- **Two secrets on stdin: the current one first.** When two `-stdin`
  flags share standard input, the current secret is the first line and
  the new one the second, and each flag's help says which line it reads.
  This changes the order for `oath set-password` (current password, then
  new) and `piv change-management-key` (current key, then new); both
  read the new one first before. `otp add` and `oath add` read the seed
  first, then the PIN or password. `prog seed --hex-stdin` /
  `--base32-stdin` now read one line, not all of stdin. ([#165])
