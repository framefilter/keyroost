- **A Feitian key that showed as an IDPrime card is known as Feitian.**
  keyroost took the PIV application of one Feitian key (USB 096E:086A)
  for a Gemalto/Thales IDPrime, with its reset switched off. It is now
  sent Feitian's commands: `piv reset` and the app's reset work (the key
  asks for a touch), the PIN tries show, and keys are generated and
  imported as RSA-1024, RSA-2048 or P-256, the types it holds. Checked
  on one key with the command line. ([#274])
