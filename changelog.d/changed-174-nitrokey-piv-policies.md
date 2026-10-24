- **No PIN or touch policy for new PIV keys on a Nitrokey 3.** On firmware
  newer than 1.8.3, up to 1.9.1, `piv key generate` and the app's Generate
  dialog used to warn about a PIN or touch policy and then send it.
  Nitrokey's published PIV source shows that this firmware ignores those
  settings and has nowhere to store one, so such a key never asked for a
  touch and asked for the PIN only as its slot always does. keyroost now
  refuses a policy other than `default` on these keys, as it already did on
  older firmware; `--force` in the CLI or Enable Anyway in the app still
  sends it. ([#174])
