- **Always-UV is set, not toggled.** `fido config always-uv enable` and
  `fido config always-uv disable` replace the `fido always-uv` toggle, so
  a script always knows the state it leaves. Each one does nothing, and
  says so, when the key is already in that state. ([#165])
