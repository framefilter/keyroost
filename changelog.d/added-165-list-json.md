- **Numbered `list` and `list --json`.** `list` numbers each key (sorted by
  serial, so a number can change when keys are added or removed), and
  `--json list` prints `{"keys": [...]}`, one row per key with the exact
  `--device` value that selects it. `list --device` shows just that key.
  ([#165])
