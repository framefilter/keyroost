- **`molto import --in` follows the shared import rules.** An entry the
  Molto2 can't store (for example a SHA-512 code or a 45-second period) is
  skipped with the reason instead of refusing the whole file, and entries
  past slot #99 are skipped. An entry with no issuer or account no longer
  takes a slot. The preview, the one question before writing (`--yes` in
  a script), the report and `--json` are the same as `oath import`.
  `--dry-run` shows which slots are in use when a Molto2 is connected
  (`--device` picks which one). ([#170])
