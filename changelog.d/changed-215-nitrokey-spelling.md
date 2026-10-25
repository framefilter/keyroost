- **Nitrokey is spelled Nitrokey.** `piv info` and the app's PIV header wrote
  "NitroKey"; `piv --json info` now reports
  `"applet_fingerprint": "Trussed::Nitrokey"` (was `Trussed::NitroKey`).
  ([#215])
