- **SSH certificates stored with `fido2-token` export again.**
  `fido2-token -S -b` stores the `-cert.pub` file's text, while `fido ssh
  export`, `fido ssh list` and the app's export only recognized OpenSSH's
  binary form, so they reported no certificate. Both forms are read now,
  and a stored text file is written back byte for byte, comment included.
  Certificates an older libfido2 stored zlib-wrapped are read too, as
  libfido2 itself reads them. ([#254])
