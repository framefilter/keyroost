- **`piv export-cert` writes PEM by default.** `piv export-cert --slot 9a`
  at a terminal now prints the certificate instead of refusing. Add
  `--format der` for the raw DER bytes the command wrote before. ([#165])
