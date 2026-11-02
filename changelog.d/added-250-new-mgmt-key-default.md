- **Setting a PIV management key back to the factory default is one step.**
  `piv mgmt-key change --new-mgmt-key default` sets the default keyroost
  knows for that key (a Token2's isn't YubiKey's), and the app's change
  dialog has a "Use the factory default" link next to "Generate random
  key". ([#250])
