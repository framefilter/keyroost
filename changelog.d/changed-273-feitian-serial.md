- **A Feitian key shows its own serial.** keyroost now reads the serial
  of a Feitian key with the OTP applet from the key itself, the one
  Feitian's own software shows. Before, such a key showed the serial
  field of its OpenPGP applet, 00000001 on both keys measured, or none
  when it has no OpenPGP applet. Checked on three keys of two products,
  the ePass FIDO NFC Plus and the BioPass FIDO Pro. A Feitian key named
  before this release may need its name set again. ([#273])
