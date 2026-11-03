- **Importing a P-256 key into a Token2 PIN+ no longer warns.** keyroost's
  support list had no entry for it, so `piv key import` and the app said
  "keyroost's list has no entry for this key yet"; a PIN+ Dual Ace R3.4
  imports P-256 keys and passes the self-test. Other algorithms' imports
  on Token2 stay unverified. ([#250])
