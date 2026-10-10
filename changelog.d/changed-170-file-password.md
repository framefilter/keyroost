- **`molto import --file-password`.** An encrypted Aegis export's password
  now comes from `--file-password env:NAME` or `--file-password stdin`, the
  same flag `oath import` and `otp import` use (v0.12's `import-file
  --password-env` / `--password-stdin` are refused with an error naming
  it). ([#170])
