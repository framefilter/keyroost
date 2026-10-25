- **A certificate can go into a PIV slot that has no key yet, in the app too.**
  The app used to disable Import certificate for such a slot; it now allows
  it, as the CLI and other tools do, and both say the certificate won't work
  until a matching key is put in the slot. ([#215])
