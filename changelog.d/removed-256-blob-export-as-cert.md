- **`fido blob export --as-cert` is gone.** It only recognized an SSH
  certificate stored unencrypted, but FIDO2 clients such as `fido2-token`
  store it encrypted under its credential, as the standard specifies, so
  it failed on the certificates they store. Save one with `fido ssh
  export` (in the app, "Save certificate…" on the Passkeys tab);
  `--as-cert` now says so. `fido blob export` and the Storage tab's Export
  save the stored bytes as they are, and `fido blob list` / `show` and
  their `--json` no longer have an `ssh-cert` kind or `ssh_cert` field.
  ([#256])
