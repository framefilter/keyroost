- **A FIDO2 key with no serial number can be reset when it is the only key
  plugged in.** The app refused such a key outright. The app and
  `keyroostctl` now follow one rule: with other keys connected, the reset
  is refused before anything is wiped, naming the keys to unplug. ([#221])
