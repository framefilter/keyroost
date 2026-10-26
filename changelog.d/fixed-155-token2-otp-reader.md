- **A failed reader exchange no longer stops the OTP command after it.** With
  a Token2 smart card in a contact reader, `otp list` stopped with "An
  attempt was made to end a non-existent transaction": keyroost's check of
  the card's settings failed, and the card answered nothing after that.
  keyroost now resets the card and selects the OTP applet again after a
  failed exchange, so the command goes on, and `--debug` shows the reader's
  error. ([#155])
