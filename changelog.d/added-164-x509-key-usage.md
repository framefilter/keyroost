- **X.509 key usage for PIV certificates and requests.** Self-signed
  certificates and CSRs carry a keyUsage extension, in the GUI and with
  `piv self-sign` / `piv request-cert --key-usage`. By default it is the
  slot's standard PIV usage, marked critical; `--key-usage undefined` (or
  "Undefined" in the GUI) writes none. Contributed by @episource. ([#164])
