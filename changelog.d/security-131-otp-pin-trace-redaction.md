- **The `--debug` trace no longer prints Token2 OTP PIN material.** The
  PIN-bearing commands — `SET_OTP_PIN`, `CHANGE_OTP_PIN`, and the PIN-carrying
  forms of `VERIFY_OTP_PIN` (a plain PIN verify, and the R3.4 Bio3
  fingerprint-protection toggle) — now have their request bodies length-redacted
  in the trace, the same as seed writes. The 1-byte `VERIFY` forms that carry no
  secret (lock, fingerprint verify) still show in full. ([#131])
