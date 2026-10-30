- **PIV and OpenPGP ask for a touch only where the key may want one.** The
  CLI's "touch the key if it blinks" lines and the app's touch banner came
  up for every PIV and OpenPGP key operation. Signing, decrypting,
  authenticating, certificate requests, self-signed certificates and the
  PIV self-test now ask only when the key's touch setting isn't off (or
  the card doesn't report one). Generating and importing keys no longer
  ask on a YubiKey, nor for OpenPGP on a Nitrokey; a PIV import still asks
  when its self-test uses a touch-protected key. A Nitrokey 3 with
  firmware 1.9.1 or later never asks for PIV. ([#244])
