- **Imported codes can require a touch.** The app's import dialog has
  "Require touch for every code" and a box on each code's row; `oath
  import` and `otp import` take `--touch` (every code they write) or
  `--touch-for NAME`, repeated, for the codes named as the preview shows
  them. The preview marks them "(touch)" and `--json` has a `touch` field
  per entry. A Nitrokey 3 asks for a touch to save each such code, and
  the import says so. ([#252])
