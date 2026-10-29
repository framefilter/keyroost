- **The idle lock also wipes a pasted otpauth:// link.** The Molto2's
  "Paste an otpauth:// URI" box holds the account's secret but wasn't on the
  idle lock's list, because the box isn't masked. Each form now keeps one
  list of its secret fields, which both its own wipe and the idle lock use,
  so a field can't be wiped in one place and missed in the other. ([#233])
