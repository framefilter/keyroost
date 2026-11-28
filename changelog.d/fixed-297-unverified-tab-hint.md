- **The app's "?" on a tab says why it is there.** Hovering it always
  blamed a missing smart-card reader. For FIDO2 and the Vault it now says
  what happened: the key was reached only through its reader, where it
  answered as a U2F key (on Windows without administrator rights, it
  suggests Restart as administrator so keyroost can check over USB), or
  its USB FIDO interface gave no clear answer. ([#297])
