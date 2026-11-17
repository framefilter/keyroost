- **A Molto2 can be named, and its name shows as soon as it's plugged in.**
  keyroost reads the serial printed on the token with the token's own
  keyless `get info` and nothing else: the app once per plug-in,
  `keyroostctl` once per command that lists keys, names one or works on a
  Molto2 (not `fido`, `oath` and the like). The token's row then shows that
  serial, `keyroostctl name set` names it, and `--device` takes the name.
  Until now a scan never connected to a Molto2, so it could be named only
  in the app, after opening it. A token that doesn't answer is asked at
  most three times per plug-in, and opening it in the app fills the serial
  in. ([#266])
