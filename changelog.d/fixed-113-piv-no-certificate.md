- **PIV slots say what keyroost can tell about the key.** `piv info` and the
  GUI used to call every slot without a certificate "empty". A slot without
  a certificate now reads "empty" when the card says it holds no key, "key
  present, no certificate" when the card confirms a key, and "no
  certificate (a key may be present)" when keyroost can't tell. keyroost
  can't tell on cards where it doesn't use GET METADATA's key type, and on
  cards that answer GET METADATA without key details for empty slots, such
  as Nitrokey and Token2 PivApplet-based cards: slots on these cards that
  read "empty" before now read "no certificate (a key may be present)". On
  a YubiKey, a slot with a key but no certificate now reads "key present,
  no certificate" in the CLI (it said "empty"). JSON output is
  unchanged. ([#113])
