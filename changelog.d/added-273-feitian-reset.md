- **Feitian OTP can be reset.** `feitian reset` resets a Feitian key's
  OTP applet, the app's Feitian OTP tab has a Reset button, and
  `factory-reset` now resets that applet too instead of leaving its
  accounts on the key. The key resets once it is touched. Afterwards
  keyroost lists the applet's three slots and says the accounts are
  wiped only when every slot reads empty; otherwise it names the slot
  that still holds accounts, or that couldn't be read, and the reset
  counts as failed. The reset was checked on an ePass FIDO NFC Plus with
  accounts in its default slot, on its own and as a `factory-reset`
  step. ([#273])
