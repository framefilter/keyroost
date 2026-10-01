- **The AppImage starts on systems without the PC/SC library.** It used to
  refuse to launch when `libpcsclite.so.1` wasn't installed. It now still
  prefers the system's own library (needed to match the system's `pcscd`),
  and otherwise falls back to a bundled copy: keyroost starts, FIDO works,
  and the smart-card features report unavailable until `pcscd` is
  installed. ([#157])
