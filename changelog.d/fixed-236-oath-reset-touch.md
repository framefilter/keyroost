- **Resetting the Authenticator asks for a touch only on keys that want
  one.** `oath reset`, the app's Reset applet and a whole-key factory reset
  said "touch the key if it blinks" on every key; now on keys whose
  Authenticator app confirms a reset with a touch, such as a Nitrokey 3. A
  YubiKey resets without one. ([#236])
