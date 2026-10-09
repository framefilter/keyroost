- **Two secrets on stdin: the current one first.** When two flags read
  `stdin`, the current secret is the first line and the new one the
  second, and each flag's help says which line it reads. This changes the
  order for `oath password set` (current password, then new) and `piv
  mgmt-key change` (current key, then new); both read the new one first
  before. `otp add` and `oath add` read the seed first, then the PIN or
  password. On `molto`, `--customer-key stdin` is always the first line,
  before the seed, URI or new key. `prog seed set --seed stdin` reads one
  line, not all of stdin. ([#165])
