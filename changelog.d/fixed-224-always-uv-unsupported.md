- **"Always require user verification" is only offered on keys that report
  it.** Pressing Toggle on a key without the `alwaysUv` option failed with
  "authenticator returned CTAP2 status 0x02". The app now leaves the row
  out for such keys, and `fido config always-uv` says the key doesn't
  support it. ([#224])
