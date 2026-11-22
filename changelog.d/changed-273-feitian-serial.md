- **A Feitian key shows its own serial.** keyroost now reads the serial
  of a Feitian key with the OTP applet from the key itself, the one
  Feitian's own software shows. Before, such a key showed the serial
  field of its OpenPGP applet, 00000001 on both keys measured, or none
  when it has no OpenPGP applet. A name saved under the old value does
  not follow the key: name it again. Checked on three keys of two
  products, the ePass FIDO NFC Plus and the BioPass FIDO Pro. ([#273])
