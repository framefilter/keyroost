- **Authenticator codes no longer go stale on screen.** The codes on the
  Authenticator tab and the Overview are read again when their time window
  rolls over, as the OTP tab already did; before, a code stayed up past its
  window while the countdown kept cycling. A code read on demand for a
  counter-based (HOTP) account stays shown across these refreshes. ([#190])
