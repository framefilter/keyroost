- **`piv cert export` writes PEM by default.** `piv cert export --slot 9a`
  at a terminal now prints the certificate instead of refusing. Add
  `--format der` for the raw DER bytes `piv export-cert` wrote before.
  ([#165])
