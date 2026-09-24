- **PIV certificates too large for a slot can be stored compressed.**
  keyroost can now write a certificate in the PIV standard's gzip form
  (CertInfo `0x01`, NIST SP 800-73-4). By default it stores certificates
  uncompressed and only compresses one the card refuses as too large (about
  3 KB on a YubiKey), saying so when it does. `piv import-cert` and
  `piv self-sign` take `--compress` / `--no-compress`, and the GUI's Import
  certificate and Self-signed dialogs have a matching Compression choice.
  Every compressed write is read back and checked. `piv status` and the GUI
  show which certificates are stored compressed. ykman and OpenSC read
  them; whether Windows' built-in smart-card driver and macOS's built-in PIV
  support do has not been verified yet (testers welcome in [#152]). ([#154])
