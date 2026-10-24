- **Authenticator works on the Nitrokey 3.** On current Nitrokey 3 firmware
  every Authenticator command failed with "conditions of use not satisfied":
  the key holds a reply back until it is asked for with the standard
  GET RESPONSE command, and keyroost only knew the YubiKey's way of asking.
  keyroost now asks each key the way it expects, so accounts can be listed,
  added, read and deleted. Saving or deleting an account that requires a
  touch asks for a touch on a Nitrokey 3; the CLI and the app now say so,
  and a missed touch gets a message that says to try again and touch the key.
