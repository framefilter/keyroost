- **Codes for OATH entries named `60/…` use their period.** `oath code`
  (without `--period`) and the GUI computed them at 30 seconds, so they
  were wrong. `--period` now defaults to the name's `period/` prefix, and
  the GUI shows the period next to the code. ([#170])
