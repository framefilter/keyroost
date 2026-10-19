- **FIDO-only keys appear when plugged in.** The app noticed new keys only
  through their smart-card reader, so a key with just FIDO (no smart-card
  interface) showed up or disappeared only after Refresh. It now watches
  the FIDO key list too and rescans when a key comes or goes. ([#189])
