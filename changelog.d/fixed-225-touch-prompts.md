- **keyroost asks for a touch wherever the key needs one.** Over USB, the
  CLI and the app now say "touch your key" whenever the key reports it is
  waiting for a touch. Over a smart-card connection they say so up front
  where a touch is known or possible: `oath code` and `oath delete` on a
  touch account, the factory reset's OATH step, OpenPGP key import and
  backup restore, and Nitrokey 3 code replacement. The app's banner
  follows the key, and no longer appears while unlocking. ([#225])
