- **Authenticator works on the Nitrokey 3.** On current Nitrokey 3 firmware
  every Authenticator command failed with "conditions of use not satisfied":
  the key holds a reply back until it is asked for with the standard
  GET RESPONSE command, and keyroost only knew the YubiKey's way of asking.
  keyroost now asks each key the way it expects, so accounts can be listed,
  added, read and deleted. A Nitrokey 3 asks for a touch to reset its
  Authenticator app, to delete any account, and to save or read one that
  requires a touch; the CLI and the app now say so, and a missed touch gets
  a message that says to try again and touch the key. ([#208])
- **Authenticator codes no longer drop out while a browser is open.** A
  browser checking the key for smart-card certificates could slip its own
  commands in between keyroost's, and the app then showed **Read code** on
  ordinary accounts. keyroost now keeps the key to itself for the length of
  each Authenticator read or change. ([#208])
- **The Nitrokey 3's firmware version shows in the app.** The key header
  showed "fw 0.0.0", the placeholder the key's FIDO side reports; it now
  shows the version from the key's admin application. ([#208])
