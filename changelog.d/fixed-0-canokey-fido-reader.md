- **A CanoKey's FIDO2 side answers through its smart-card reader again.**
  From firmware 3.1.2 a CanoKey answers FIDO2 on its own USB reader only
  under CanoKey's private selector, which keyroost now tries first, so
  FIDO2 over the reader works on that firmware too; Windows lets a
  program that isn't administrator use it. The key answers that
  selector as a U2F key, so keyroost also reads its getInfo there and
  lists FIDO2 as confirmed rather than `FIDO2?`. A FIDO2 reset is not sent
  through that reader, since power-cycling it doesn't restart the key:
  keyroost refuses it before asking anything and says to reset over FIDO
  HID or with `factory-reset`. ([#0])
