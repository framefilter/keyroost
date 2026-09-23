- **PIV certificate imports that are too large now say so.** Importing a
  certificate of about 3 KB or more could fail with a raw PC/SC error
  ("An attempt was made to end a non-existent transaction") before the card
  answered, so the command-chaining fallback never ran. keyroost now retries
  such an import with command chaining. A certificate that fits (for
  example 3048 bytes on a YubiKey 5.7) imports. One the card refuses gets
  "the certificate (N bytes) is too large for <slot>", or "the card has no
  room left" when its storage is full. A refused import leaves the slot's
  existing certificate unchanged. ([#151])
