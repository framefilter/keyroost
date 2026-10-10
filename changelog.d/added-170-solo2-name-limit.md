- **Solo 2 names are capped at 127 bytes.** `oath add`, `oath import` and
  the GUI refuse a longer Solo 2 name before sending it: a 128-byte name
  made the key stop responding until it was unplugged. ([#170])
- **YubiKey 4 prefix names.** On YubiKey 4 firmware 4.0 to 4.3.4, `oath
  add`, `oath import` and the GUI refuse a name that is the start of
  another name already on the key, following the same rule as Yubico's
  `ykman`. ([#170])
