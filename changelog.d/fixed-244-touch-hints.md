- **PIV and OpenPGP ask for a touch only where the key may want one.** The
  CLI's "touch the key if it blinks" lines and the app's touch banner came
  up for every PIV and OpenPGP key operation. Signing, decrypting,
  authenticating, changing a key's expiry, certificate requests,
  self-signed certificates and the PIV self-test now ask only when the
  key's touch setting isn't off (or the card doesn't report one).
  Generating and importing keys no longer ask on a YubiKey, nor for
  OpenPGP on a Nitrokey 3; a PIV import still asks when its self-test uses
  a touch-protected key. A Nitrokey 3 with firmware 1.9.1 or later doesn't
  ask for PIV at all. The app's banner for these steps says "Touch the key
  if it blinks…"; "Touch your key to continue…" stays for a key that
  reports it is waiting. ([#244])
- **A PIV step that timed out waiting for a touch says so.** The error read
  "needs a management-key auth or PIN that wasn't satisfied" even when the
  PIN was accepted and only the touch was missing; it now names the touch
  too. ([#244])
