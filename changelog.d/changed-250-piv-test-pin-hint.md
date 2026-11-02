- **A PIV self-test refused for want of a PIN says to give one.** `piv test`
  asks for no PIN of its own, and its error didn't say why the card
  refused; it now points at `--pin` when none was given. The app's Test
  dialog points at its PIN box the same way. ([#250])
