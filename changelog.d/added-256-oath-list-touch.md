- **`oath list` shows which accounts need a touch.** It marks them
  "(touch)", as `otp list` does, and `--json` gains `touch_required` per
  account, so an `oath import --touch-for` can be checked from the
  command line. On a YubiKey an HOTP account always reads `false`: the key
  doesn't say. ([#256])
