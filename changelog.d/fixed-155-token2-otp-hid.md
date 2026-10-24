- **Token2 OTP works over USB on PIN+ keys with firmware 2.1.** On these
  keys `otp list`, the app's On-device OTP tab and every other OTP command
  failed with "unexpected status word 0x0105": the key's FIDO interface
  didn't accept the way keyroost framed OTP commands. keyroost now sends
  them through the CTAPHID vendor command Token2 documented, and keeps the
  earlier framing for keys that don't answer it. A code that needs a touch
  says "touch your key" when the key asks for one. ([#155])
