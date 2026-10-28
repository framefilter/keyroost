- **The idle lock also closes what a typed password opened.** A file read
  for import, an OpenPGP key set made or read from a backup, and a .p12
  key now start the idle clock, and the dialog holding them closes when it
  runs out, saying why. The On-device OTP PIN boxes clear their typed
  history like every other secret box. ([#226])
