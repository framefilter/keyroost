- **A code you touched the key for no longer vanishes at the 30-second
  mark.** In the app, **Read code** on an account that requires a touch now
  works out the code for 10 seconds ahead, as Yubico Authenticator does, so a
  code read near the end of its window is the next window's code. The code
  stays on screen until its own window ends instead of being cleared by the
  next refresh. ([#217])
