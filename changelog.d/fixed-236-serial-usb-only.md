- **A Token2 key or YubiKey seen only over USB shows its serial, and its
  name.** Where nothing pairs a key's USB side with a smart-card reader (a
  Token2 PIN+ on Linux, whose card side has no reader there; a YubiKey with
  its smart-card interface off), its row had no serial, so a name given to
  it by serial didn't show either, though a Token2's firmware release was
  worked out from that same serial. A device scan now asks such a key for
  its serial: once per plug-in on Linux and macOS; on Windows, where a
  key's USB position can't tell two identical keys apart, at each scan,
  keeping the last answer through a scan the key misses so it doesn't
  vanish from the row. ([#236])
