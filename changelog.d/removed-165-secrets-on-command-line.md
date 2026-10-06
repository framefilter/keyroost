- **No secret on the command line.** The flags that took a secret as a
  plain argument are gone, because the command line ends up in shell
  history and `ps`: `molto --key` / `--key-ascii` (use `--key-env` /
  `--key-ascii-env`), `molto seed` and `prog seed` `--hex` / `--base32`
  (use `--hex-env`, `--hex-stdin`, `--base32-env` or `--base32-stdin`),
  and `molto customer-key --hex` / `--ascii` (use the `-env` / `-stdin`
  forms). `molto import` no longer takes the `otpauth://` URI as an
  argument: pipe it with `-`, use the new `--uri-env VAR`, or `--qr
  IMAGE`. Each removed flag is refused with an error that names its
  replacement and doesn't repeat the value. ([#165])
