- **`piv mgmt-key change` refuses an algorithm the key doesn't take**,
  as the app's algorithm list already did: a cipher keyroost's list marks
  unsupported on the selected key (AES-256 on a HID Crescendo, say) is
  refused before anything is sent, unless `--force`. Before, the command
  was sent anyway. ([#297])
