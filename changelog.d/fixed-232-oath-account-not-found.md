- **Every key says the same when an Authenticator account isn't there.**
  `oath delete` and `oath code` for a name the key doesn't hold now stop with
  `no OATH credential named "…" on this key` before anything is sent. A
  YubiKey used to answer with a bare status word, and a Solo 2 reported the
  delete as done. In the app, deleting an account that was removed elsewhere
  since the list was read says so and refreshes the list. ([#232])
