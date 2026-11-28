- **`piv mgmt-key change` refuses an algorithm the key doesn't take**,
  as the app's algorithm list already did: a cipher keyroost's list marks
  unsupported on the selected key (AES-256 on a HID Crescendo, say) is
  refused before anything is sent, and the refusal names the algorithms
  the key takes ("This key takes 3DES or AES-256: pass --algorithm 3des
  or --algorithm aes256."), with `--force` as the last resort. That
  includes the AES-192 default on keys whose list rejects it, such as a
  Nitrokey 3: the default is never swapped silently. Before, the command
  was sent anyway. keyroost's list now also marks AES-128 and AES-192
  unsupported on Nitrokey 3 firmware 1.9.0 and 1.9.1, where it had
  marked them unverified. ([#297])
