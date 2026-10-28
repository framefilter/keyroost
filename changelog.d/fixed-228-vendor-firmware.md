- **Each key's firmware is shown the way its maker states it.** A Solo 2
  showed 2.3.196 for firmware 2.964, and a Token2 PIN+ showed 2.1.2; it now
  shows its release (for example "R3.4"), named from its serial number as
  Token2 publishes. In `keyroostctl fido info` and the app's key header;
  `fido --json info` gives `firmware: null` when a key doesn't say. ([#228])
