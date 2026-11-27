- **`piv mgmt-key change` refuses an algorithm the key doesn't take**,
  as the app's algorithm list already did: a cipher keyroost's list marks
  unsupported on the selected key (3DES on a CanoKey 3.1, say) is refused
  before anything is sent, unless `--force`. Before, the command went to
  the key, which refused it. ([#0])
