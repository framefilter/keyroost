- **Authenticator codes no longer go stale on screen.** The codes on the
  Authenticator tab and the Overview are read again when their time window
  rolls over, as the OTP tab already did; before, a code stayed up past its
  window while the countdown kept cycling. A code read on demand for a
  counter-based (HOTP) account stays shown across these refreshes. An
  account that requires a touch gets a **Read code** button instead of being
  re-read each window, so the key doesn't wait for a touch every 30 seconds
  and the other accounts' new codes aren't held back meanwhile. ([#190])
