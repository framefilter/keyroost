- **Feitian OTP without the smart-card reader.** When a Feitian key has
  no reader on the computer, or its reader can't be opened, the
  `feitian` commands and the app's Feitian OTP tab reach the applet
  through the key's FIDO HID interface instead, as Feitian's own client
  does. A key seen only that way is listed with `FEITIAN-OTP?`. On
  Windows this needs an administrator, like FIDO2. Checked on an ePass
  FIDO NFC Plus and a BioPass FIDO Pro. ([#273])
