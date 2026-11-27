- **CanoKey keys are recognized.** A CanoKey (USB `20A0:42D4`) is listed
  as a CanoKey with its model, such as `Canary`, instead of as a
  Nitrokey, and its smart-card reader and FIDO interface show as one key,
  on macOS too. The CanoKey support in this release follows CanoKey's
  firmware source (3.1.2) and its own tools, and was checked over USB on
  a CanoKey Canary with firmware 3.1.2 on Windows; NFC, macOS and Linux
  are not checked on a key yet. ([#0])
