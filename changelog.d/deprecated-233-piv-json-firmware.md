- **`piv --json info` names the firmware `firmware`,** like
  `fido --json info`. Its old name, `version_firmware`, still carries the
  same value for now but is deprecated; scripts should read `firmware`.
  `fido --json info`'s `ctap2.firmware_version` keeps its name: it is the
  FIDO spec's raw getInfo number, named after the spec like the rest of
  that block. ([#233])
