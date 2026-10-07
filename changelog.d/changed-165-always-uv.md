- **Always-UV is set, not toggled.** `fido config enable-always-uv` and
  `fido config disable-always-uv` replace the `fido always-uv` toggle, so a
  script always knows the state it leaves. Each one does nothing, and says
  so, when the key is already in that state. ([#165])
