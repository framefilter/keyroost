- **Feitian OTP can be reset.** `feitian reset` removes every account
  from a Feitian key's OTP applet, the app's Feitian OTP tab has a Reset
  button, and `factory-reset` now resets that applet too instead of
  leaving its accounts on the key. The key resets once it is touched.
  The applet's own reset and the whole-key reset with this step were
  checked on an ePass FIDO NFC Plus. ([#273])
