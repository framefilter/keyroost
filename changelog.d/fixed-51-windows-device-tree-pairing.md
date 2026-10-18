- **One row per key on Windows, even with two keys of the same make.** A key's
  FIDO interface and its smart-card reader are now recognized as one physical
  key from where both sit in the Windows device tree, the same evidence Linux
  gets from the USB bus. Neither the key nor the card is opened to find out.
  Under `--debug`, `keyroostctl list` prints what Windows reported for each
  key (`devtree` lines). Library users: `usb_bus` / `usb_address` on
  `HidDevice`, `ReaderProbe` and `YubiKeyCcid` are replaced by one
  `usb_device` field. Keys are also named properly there: "YubiKey" rather
  than "YubiKey 0", and "Solo 2" rather than "0". ([#51])
