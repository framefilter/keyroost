- **A key keeps its full model name once read.** Opening a key reads its
  model ("YubiKey 5 Series with NFC") and firmware; until now the sidebar
  and header went back to the shorter USB name ("YubiKey") after another
  key was selected and the list refreshed. The name and firmware now stay
  with the key until it is unplugged. The activity log also stops repeating
  "device scan: N devices found" on every refresh when nothing changed.
  ([#236])
