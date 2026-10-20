- **U2F-only keys are labeled U2F.** A key whose FIDO side speaks only U2F,
  such as the YubiKey NEO, was labeled FIDO2. keyroost now asks each key's
  FIDO interface which protocol it speaks and labels it U2F when that is all
  it does, in `keyroostctl list` (and `list --json`) and in the app, which
  no longer offers a FIDO2 tab or a FIDO2 reset step for it. ([#201])
