- **No secret on the command line.** The flags that took a secret as a
  plain argument are gone, because the command line ends up in shell
  history and `ps`: `molto --key` / `--key-ascii` (use `--customer-key
  env:NAME`, with `--customer-key-encoding ascii` for an ASCII key),
  `molto seed` and `prog seed` `--hex` / `--base32` (use `--seed env:NAME`
  or `--seed stdin`, with `--encoding hex` for hex), and `molto
  customer-key --hex` / `--ascii` (use `--new-customer-key`). `molto
  import` no longer takes the `otpauth://` URI as an argument: use `--uri
  env:NAME`, `--uri stdin`, `--qr IMAGE`, or the prompt. Each removed flag
  is refused with an error that names its replacement and doesn't repeat
  the value. ([#165])
