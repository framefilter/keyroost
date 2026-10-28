- **A factory reset asks for the touch that erasing OTP entries needs.** On a
  Token2 key the reset's OTP step waited silently for a button press and then
  failed with "timed out waiting for a button press on the key". The app's
  Factory reset card now says to touch the key while the reset runs, and
  `keyroostctl factory-reset` prints a touch line over a smart-card reader
  too. ([#218])
