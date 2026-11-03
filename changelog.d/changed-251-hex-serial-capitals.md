- **Hex serials show in capitals everywhere.** A Nitrokey's serial read
  `42682ef7` in the CLI's key line, the app header and the factory-reset
  question, but `42682EF7` in `openpgp info`; all now show capitals, as
  GnuPG does. `-d serial:` still matches either case. ([#251])
