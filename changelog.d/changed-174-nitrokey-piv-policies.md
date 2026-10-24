- **No PIN or touch policy for new PIV keys on a Nitrokey 3.** On firmware
  newer than 1.8.3, up to 1.9.1, `piv key generate` and the app's Generate
  dialog used to warn about a PIN or touch policy and then send it.
  According to Nitrokey's published PIV source, this firmware doesn't apply
  those settings and has nowhere to store one; its PIN rule is fixed per
  slot and it has no touch requirement. keyroost now
  refuses a policy other than `default` on these keys, as it already did on
  older firmware; `--force` in the CLI or Enable Anyway in the app still
  sends it. ([#174])
