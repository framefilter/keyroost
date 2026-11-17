- **A Molto2 can be named, and its name shows as soon as it's plugged in.**
  keyroost reads the serial printed on the token with the token's own
  keyless `get info` and nothing else: the app once per plug-in,
  `keyroostctl` once per command that lists keys, names one or works on a
  Molto2. Other commands (`fido`, `oath` and the like) send it nothing,
  unless their `--device` matched no key: then it's read so the refusal
  can say that the value names the Molto2, which can't do that. The
  token's row shows that serial, `keyroostctl name set` names it, and
  `--device` takes the name. Until now a scan never connected to a Molto2,
  so it could be named only in the app, after opening it. A token that
  doesn't answer is asked at most three times per plug-in, and opening it
  in the app fills the serial in. ([#267])
