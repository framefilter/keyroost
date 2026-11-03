- **A Token2 key's serial no longer appears in full in `--debug` traces.**
  The OTP layer printed it while the layer below it, and keyroost's own
  probe notes, kept it out; it's now redacted there too. ([#251])
