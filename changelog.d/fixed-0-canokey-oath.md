- **Authenticator codes on a CanoKey are saved the way the key keeps
  them.** A CanoKey adds one to an HOTP counter before it computes a
  code, so keyroost now writes one less and the first code is the one the
  service expects; an account that starts at counter 0 starts at 1 there,
  and `oath add`, `oath import` and the app say so. A name or secret
  longer than the 64 bytes a CanoKey stores is refused with a message
  that says so, and replacing an account on import works (the key answers
  a name it already holds with `6985`, which keyroost took as a password
  request). `oath reset` and the app's Reset ask for the CanoKey Admin PIN
  (`--canokey-admin-pin`), since a CanoKey resets OATH through its Admin applet.
  ([#0])
