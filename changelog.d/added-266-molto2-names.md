- **A Molto2 can be named, and its name shows as soon as it's plugged in.**
  A device scan reads the serial printed on the token once per plug-in,
  with the token's own keyless `get info` and nothing else, so the token's
  row shows that serial, `keyroostctl name set` names it, and `--device`
  takes the name. Until now a scan never connected to a Molto2, so it
  could be named only in the app, after opening it. A token that doesn't
  answer is asked at most three times per plug-in; its name then shows once
  it's opened, as before. ([#266])
