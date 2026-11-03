- **A PIV reset says what the PIN, PUK and management key went back to.**
  `piv reset`, setting retry counts and the app's Reset applet said only
  "factory defaults", which cost tries on keys whose defaults aren't
  YubiKey's: a Token2 PIN+ goes back to PIN 865362 and PUK 86536286. They
  now name the defaults when keyroost knows them. ([#251])
