# Changelog

All notable changes to keyroost are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.16.0] - 2026-11-11

### Added
- **`piv test` works on a slot with a key but no certificate.** It tested
  only against the slot's certificate, so an X25519 key (which can't sign
  one) or a freshly generated key couldn't be tested at all. Such a slot is
  now tested against the public key the card reports for it (GET METADATA,
  e.g. a YubiKey 5.3 or later), and the result says no certificate was
  part of the test;
  `--json` adds `cert_tested`. Slots with a certificate are tested as
  before. The app's Test button follows. ([#243])
- **`fido info` names the key's model and its FIDO certification**, as the
  app's metadata card does: "Model", "Certification" (with the date it took
  effect) and "Protocol family" rows, and a `metadata` object in `--json`.
  The model table and the bundled FIDO metadata moved into a library the
  CLI and the app share, so both read the same data, including a
  `mds_data.json` you place to refresh it. ([#251])
- **Setting a PIV management key back to the factory default is one step.**
  `piv mgmt-key change --new-mgmt-key default` sets the default keyroost
  knows for that key (a Token2's isn't YubiKey's), and the app's change
  dialog has a "Use the factory default" link next to "Generate random
  key". ([#251])
- **Imported codes can require a touch.** The app's import dialog has
  "Require touch for every code" and a box on each code's row; `oath
  import` and `otp import` take `--touch` (every code they write) or
  `--touch-for NAME`, repeated, for the codes named as the preview shows
  them. The preview marks them "(touch)" and `--json` has a
  `touch_required` field per entry. A Nitrokey 3 asks for a touch to save
  each such code, and the import says so. ([#252])
- **After generating one OpenPGP key or importing a bare RSA key file,
  keyroost says how to get its public key.** Those leave a key on the card
  but no public key file; the CLI and the app now point at GnuPG's
  "Existing key from card", which builds the matching public key from the
  fingerprint and time keyroost recorded. ([#254])
- **`oath list` shows which accounts need a touch.** It marks them
  "(touch)", as `otp list` does, and `--json` gains `touch_required` per
  account, so an `oath import --touch-for` can be checked from the
  command line. It is `null` where the key doesn't say: a YubiKey doesn't
  for an HOTP account, so `oath code` for one now says to touch the key
  if it blinks. ([#256])

### Changed
- **The trace covers every connection.** `--debug` now also traces FIDO2
  through a smart-card reader, and the app's APDU trace now includes FIDO2
  traffic over USB and through a reader, plus keyroost's notes on how it
  found and paired each key. In those notes, the serial numbers the reader
  probe reports and the ones some systems put in a reader's name are
  shortened to their first and last two characters. ([#230])
- **The activity log covers every tab.** Changes and their errors in the
  Authenticator, On-device OTP, FIDO2 and OpenPGP tabs, a FIDO2 reset on
  its own, and an import that wrote nothing now write a line, as the PIV
  and Molto2 tabs' changes already did. A change whose re-read afterwards
  fails is still logged as made. Lines name no Authenticator account, and
  show your home folder as `~`. A failure an automatic refresh keeps
  hitting is logged once. With APDU trace on, a read or refresh that
  writes no line of its own, such as reading Authenticator codes, gets one
  named after it, so its traffic is never dropped; the checkbox explains
  this when you hover it. `fido config` and `fido fingerprint` say "this
  key does not support" like the other settings commands. ([#231])
- **A key keeps its full model name once read.** Opening a key reads its
  model ("YubiKey 5 Series with NFC") and firmware; until now the sidebar
  and header went back to the shorter USB name ("YubiKey") after another
  key was selected and the list refreshed. The name and firmware now stay
  with the key until it is unplugged. The activity log also stops repeating
  "device scan: N devices found" on every refresh when nothing changed.
  ([#236])
- **`openpgp info` shows a YubiKey's or Nitrokey's serial as the key
  names it.** It read the card's four serial bytes as one number:
  `931162176 (0x37806840)` for YubiKey 37806840, `1114124023
  (0x42682EF7)` for Nitrokey 3 42682EF7. It now shows those bytes the way
  GnuPG does, which is the key's own serial; the app's OpenPGP tab, the
  reset message and `--json`'s `serial` field (a string, as before) follow.
  A Token2 key still shows its full serial when its OTP applet answers.
  ([#237])
- **Building from source needs Rust 1.89** (was 1.87) for the libraries
  and the CLI; the app still needs 1.92. Packaged builds are unaffected.
  The crypto libraries keyroost uses moved to their current generation
  together (AES, SHA-2, HMAC, AES-GCM, PBKDF2, scrypt, 3DES, RC2, the OS
  random source, Ed25519 and X25519), and they now raise their own
  minimum Rust in patch releases. Keys, backups and imports work as
  before. If the operating system can't supply random numbers while
  keyroost makes an OpenPGP key (other than RSA) or a backup, it now
  reports an error instead of crashing. ([#245])
- **`fido pin status --json` says whether a PIN is set.** It printed only
  `pin_retries`: a key with no FIDO2 PIN showed a count anyway (a Nitrokey
  3 said 8), as if one were set, or failed outright (a Token2 PIN+). It
  now prints `pin_set` too, named as in `otp pin status --json`, with
  `pin_retries` null when no PIN is set. ([#245])
- **More security keys show their FIDO metadata.** The app's bundled list
  of certified authenticators now covers every hardware key in the FIDO
  Alliance's list instead of a few vendors, so the FIDO2 overview shows the
  model, certification level and logo for many more keys. Logos published
  only as SVG, or labeled as the wrong format, now show too. ([#246])
- **The app moves to egui 0.37** (from 0.35), the GUI toolkit it is built
  on. Building the app from source now needs Rust 1.95 (was 1.92); the CLI
  and libraries stay at 1.89, and packaged builds are unaffected. ([#249])
- **The CLI names a FIDO2 key by its model, as the app does.** A key
  showed as "YubiKey" on keyroostctl's `→` line and in `list` while the
  app said "YubiKey 5 Series with NFC". The CLI now reads the targeted
  key's FIDO2 info (one quick read, no PIN) and names it by the model that
  info identifies; `list` and `--json` use the same names. Where the key
  can't be read (Windows without administrator rights) both keep its USB
  name. ([#251])
- **Hex serials show in capitals everywhere.** A Nitrokey's serial read
  `42682ef7` in the CLI's key line, the app header and the factory-reset
  question, but `42682EF7` in `openpgp info`; all now show capitals, as
  GnuPG does. `-d serial:` still matches either case. ([#251])
- **A PIV reset says what the PIN, PUK and management key went back to.**
  `piv reset`, setting retry counts and the app's Reset applet said only
  "factory defaults", which cost tries on keys whose defaults aren't
  YubiKey's: a Token2 PIN+ goes back to PIN 865362 and PUK 86536286. They
  now name the defaults when keyroost knows them. ([#251])
- **A PIV self-test refused for want of a PIN suggests giving one.** `piv
  test` asks for no PIN of its own, and its error didn't say why the card
  refused; it now says the card may want the slot's PIN and points at
  `--pin` when none was given. The app's Test dialog points at its PIN box
  the same way. ([#251])
- **A status bar along the bottom of the app says what is running.** It
  showed in one small gray line in the top bar, which a narrow window cut
  off first. The bar shows the running step with a spinner, its seconds
  once it has run 3 s, an import's progress, then what just happened for
  a few seconds (an error a little longer). Clicking it opens the
  Activity log. A touch wait still shows in its banner. ([#253])
- **A click never just vanishes while the key is busy.** Buttons that
  would start another key operation show disabled while one runs, and
  hovering one says what it waits for; a click that still arrives says
  "Still working on: …" in the status bar. ([#253])
- **Making RSA-4096 OpenPGP keys says it can take a minute** in
  `openpgp key create` too, as the app already did. ([#253])

### Fixed
- **Every key says the same when an Authenticator account isn't there.**
  `oath delete` and `oath code` for a name the key doesn't hold now stop with
  `no OATH credential named "…" on this key` before anything is sent. A
  YubiKey used to answer with a bare status word, and a Solo 2 reported the
  delete as done. In the app, deleting an account, or reading its code,
  after it was removed elsewhere says so and refreshes the list. And
  `oath code` works on a password-protected Solo 2, which keeps its unlock
  for one command only; it was refused with `6985`. ([#232])
- **The idle lock also wipes a pasted otpauth:// link.** The Molto2's
  "Paste an otpauth:// URI" box holds the account's secret but wasn't on the
  idle lock's list, because the box isn't masked. Each form now keeps one
  list of its secret fields, which both its own wipe and the idle lock use,
  so a field can't be wiped in one place and missed in the other. ([#233])
- **A Token2 key with an OTP PIN set stays reachable over USB.** Once a PIN
  was set, every on-device OTP command over USB failed with `0x0105`,
  `otp pin clear` and `otp pin status` included, in the CLI and the app,
  and `fido info` and the app's key header showed its firmware as unknown:
  the check keyroost runs to pick the key's USB channel used a command that
  a PIN-protected key refuses. keyroost now follows that refusal with the
  key's documented PIN-state read, which tells a protected key from one
  that declines the channel. Tested end to end on a PIN+ Dual Ace R3.4
  (set, wrong PIN, codes and adds under the PIN, change, clear). ([#235])
- **A PIN typed into the FIDO2 tab is wiped when the tab's state is
  replaced** (switching keys, for instance), as the other tabs' secrets
  already were. ([#236])
- **Opening the Authenticator tab on a password-protected key no longer
  says "wrong OATH password".** The app lists the accounts before you type
  anything, and the key's refusal of that first, password-less request was
  shown as a wrong password. The tab now just shows the locked box; "wrong
  OATH password" appears only after a password was sent and refused, and
  adding an account on a locked key says to unlock it first.
  ([#236])
- **Resetting the Authenticator asks for a touch only on keys that want
  one.** `oath reset`, the app's Reset applet and a whole-key factory reset
  said "touch the key if it blinks" on every key; now on keys whose
  Authenticator app confirms a reset with a touch, such as a Nitrokey 3. A
  YubiKey resets without one. ([#236])
- **A Token2 key or YubiKey seen only over USB shows its serial, and its
  name.** Where nothing pairs a key's USB side with a smart-card reader (a
  Token2 PIN+ on Linux, whose card side has no reader there; a YubiKey with
  its smart-card interface off), its row had no serial, so a name given to
  it by serial didn't show either, though a Token2's firmware release was
  worked out from that same serial. A device scan now asks such a key for
  its serial: once per plug-in on Linux and macOS; on Windows, where a
  key's USB position can't tell two identical keys apart, at each scan,
  keeping the last answer through a scan the key misses so it doesn't
  vanish from the row. ([#236])
- **`fido pin status` says when no FIDO2 PIN is set.** It printed the
  retry counter, "8 PIN attempt(s) remaining", on a key with no PIN (a
  Nitrokey 3), and on a key that refuses that question without one (a
  Token2 PIN+) it failed with `CTAP2_ERR_PIN_NOT_SET`. It now says no PIN
  is set, as the app's "No PIN configured" does. `--json` is unchanged.
  ([#237])
- **`piv cert generate --generate-key` and `piv cert request
  --generate-key` check the key type first, as `piv key generate` does.**
  They skipped keyroost's support list, so asking a YubiKey for an ECC
  P-521 key went to the card and came back as `SW=6A80`; now it stops
  before the management key is sent or anything is generated, says the
  key doesn't support it, and takes `--force` like `piv key generate`. The
  PIN- and touch-policy checks apply too. ([#237])
- **PIV slots can be typed in capitals.** `piv info` shows slots as `9A` or
  `8A`; `--slot 8A` was refused and only `8a` worked. Both work now.
  ([#237])
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
- **`otp info` over USB shows a Token2 PIN+ R3.4's whole configuration.**
  Over USB the key answered with one byte, so OTP and touch-HOTP support
  read as "unknown". keyroost sends Token2's documented request first and,
  when the answer is that short, the form Token2's own app uses. ([#249])
- **A Token2 OTP PIN the key refuses for its rules says so.** Setting or
  changing the OTP PIN to one the key won't accept reported "entry not
  found"; it now says the PIN doesn't meet the key's rules. ([#249])
- **A Token2 PIN+ R3.4 shows the serial printed on it on Windows.** Its
  row, the app header and `list` showed an 8-digit number taken from its
  OpenPGP applet, because Windows doesn't let keyroost reach the key's
  FIDO side through its reader. keyroost now reads the full serial from
  the key's OTP applet; names saved under the old number still apply.
  ([#249])
- **The app shows keyroost's icon on the title bar, the taskbar and the
  Dock** instead of the GUI toolkit's default logo. ([#249])
- **On Windows, file dialogs open in front of the app.** They had no owner
  window and could open behind keyroost. ([#249])
- **keyroostctl's piped output reads cleanly in PowerShell.** PowerShell
  decodes a program's piped or redirected output in the console's legacy
  code page, so keyroost's arrows, dashes and dots arrived as `ΓåÆ`, `ΓÇö`
  and `┬╖`. When its output goes to a pipe or a file on Windows,
  keyroostctl now writes those few characters in ASCII (`->`, `-`, `|`),
  in names too; the console, JSON and files it writes are unchanged.
  ([#249])
- **Reading a key's FIDO2 storage no longer freezes the app.** The Storage
  tab read the large-blob store on the window's own thread, so a slow key
  froze the app until it answered, and the read left nothing in the
  Activity log's APDU trace. It now runs in the background like every
  other read. ([#251])
- **`list` names every applet a reader answered.** Its per-reader line
  left out FIDO2 and OTP (a Token2 PIN+ answers both through its reader);
  the matched rows below it already showed them. ([#251])
- **The app's metadata card dates a status correctly.** It labeled the date
  of any published status "Certified since", including "Not FIDO
  Certified" and advisories; those now say "Status since". ([#251])
- **Deleting an Authenticator account that was already gone says so in the
  pane.** Only the Activity log mentioned it; the pane now shows "That
  account was no longer on the key; nothing was deleted.", as reading its
  code already did. ([#251])
- **One Refresh is one "device scan" line in the Activity log.** With
  "APDU trace" on, each rescan of a Refresh's burst added its own line;
  their traffic now goes under one line. ([#251])
- **The app's PIV retry boxes say they're the count to set.** They read
  "PIN tries 3 / PUK tries 3" on every key, which looked like the key's
  current counts (a Token2 PIN+ has 6). They're now "New PIN tries" and
  "New PUK tries", with a note that setting them resets both. ([#251])
- **Importing a P-256 key into a Token2 PIN+ no longer warns.** keyroost's
  support list had no entry for it, so `piv key import` and the app said
  "keyroost's list has no entry for this key yet"; a PIN+ Dual Ace R3.4
  imports P-256 keys and passes the self-test. Other algorithms' imports
  on Token2 stay unverified. ([#251])
- **A Token2 key's serial no longer appears in full in `--debug` traces.**
  The OTP layer printed it while the layer below it, and keyroost's own
  probe notes, kept it out; it's now redacted there too. ([#251])
- **A request that failed below the card shows its error in the trace.**
  When PC/SC itself refused a command (Windows' "access is denied", a
  removed card), `--debug` and the Activity log showed the request and no
  answer; the answer line now reads "PC/SC error: …". ([#251])
- **Long APDU trace lines in the Activity log wrap under their own
  column.** A long request continued at the left margin, under the labels;
  it now continues under its hex, broken every 4 bytes. Copy still copies
  each line whole. ([#253])
- **Changing a key's expiry on a card that records no fingerprint says
  so.** `openpgp key expiry` (and the app's Change expiry) called such a
  card's signature key a different key; it now says the card records no
  fingerprint for it, so keyroost can't tell whether it is that key.
  ([#254])
- **OpenPGP help no longer says a YubiKey always needs a touch.**
  `openpgp sign`, `authenticate`, `key generate` and `key expiry` said
  so; a touch is needed when the slot's touch setting is on. ([#254])
- **A key selected while another was busy no longer stays on "Reading
  key…".** Its first read was refused while the other key's step ran, and
  only the FIDO2 tab tried again, so the Overview kept "Reading key…"
  until the next scan. The read now starts as soon as nothing else runs,
  on any tab. ([#254])
- **SSH certificates stored with `fido2-token` export again.**
  `fido2-token -S -b` stores the `-cert.pub` file's text, while `fido ssh
  export`, `fido ssh list` and the app's export only recognized OpenSSH's
  binary form, so they reported no certificate. Both forms are read now,
  and a stored `-cert.pub` line is written back as it was, comment
  included.
  Certificates an older libfido2 stored zlib-wrapped are read too, as
  libfido2 itself reads them. ([#254])
- **App details from the Windows test round.** The window no longer opens
  larger than a small screen with display scaling (1280×800 at 125%) or
  under the taskbar; it shrinks or moves to fit (where the system says
  where the window is: not on Wayland). The import dialog draws
  again until its size settles, instead of leaving its buttons cut off
  until the mouse moved. The PIV reset confirmation no longer says it
  only works with the PIN and PUK already blocked: keyroost blocks them
  first where the key needs that. In the dark theme, an unticked checkbox
  in a dialog ("Require touch", "Use default management key") shows its
  box. The "touch your key" banner sits under the key's name and tabs
  instead of over them. The On-device OTP tab's PIN cards span the pane
  like its other cards, and removing the OTP PIN no longer shows advice
  for choosing one. ([#256])
- **A PIV change that finishes after you select another key is reported
  under its own key.** An RSA-4096 key generation on one key, say, was
  logged and shown under the key selected by the time it ended. ([#256])
- **`keyroostctl list` on Windows shows a key's serial on its FIDO line.**
  Windows reports an empty USB serial for a key that has none, and `list`
  printed a bare `serial=` instead of the serial read over the key's
  smart-card side. The app now matches a YubiKey's FIDO side by that
  serial too, as it already did on Linux. ([#256])

### Deprecated
- **`piv --json info` names the firmware `firmware`,** like
  `fido --json info`. Its old name, `version_firmware`, still carries the
  same value for now but is deprecated; scripts should read `firmware`.
  `fido --json info`'s `ctap2.firmware_version` keeps its name: it is the
  FIDO spec's raw getInfo number, named after the spec like the rest of
  that block. ([#233])

### Removed
- **`fido blob export --as-cert` is gone.** It only recognized an SSH
  certificate stored unencrypted, but FIDO2 clients such as `fido2-token`
  store it encrypted under its credential, as the standard specifies, so
  it failed on the certificates they store. Save one with `fido ssh
  export` (in the app, "Save certificate…" on the Passkeys tab);
  `--as-cert` now says so. `fido blob export` and the Storage tab's Export
  save the stored bytes as they are, the Storage tab no longer shows
  certificate details, and `fido blob list` / `show` and their `--json`
  no longer have an `ssh-cert` kind or `ssh_cert` field.
  ([#256])

## [0.15.0] - 2026-10-28

### Added
- **Import a key and certificate from a .p12/.pfx file.** `keyroostctl piv
  key import --slot 9a --in FILE` writes a private key and its certificate
  from a PKCS#12 file into a PIV slot, then tests the slot as `piv test`
  does; in the app, it's "Import key from file…" on a PIV slot.
  Legacy-encrypted files (RC2/3DES, the kind some certificate authorities
  such as Spain's FNMT still issue) open directly. keyroost checks that the
  key can take the file before it asks for the management key. A file with
  several keys is listed for `--entry N`, and `--chain-out FILE` saves the
  authority certificates, which are not written to the card. On a
  Nitrokey 3, RSA keys go into slot 9A; HID Crescendo cards aren't supported
  yet. An imported key can't be attested as generated on the key. ([#174])
- **`fido info --reader` reads a key through a smart-card reader**, as
  `fido reset --reader` already could. A key that only speaks U2F there gets
  the same line as over USB, in the app too, instead of an error. On Windows,
  where only a program running as administrator may reach a key's FIDO2 side
  through its reader, a refusal says so. With no options, `fido info` now
  picks the key the same way `fido reset` does, so with several FIDO keys
  (including one only reachable through a reader) it asks which one. ([#215])
- **`doctor` and the app say when a key's smart-card part has no reader
  (Linux).** When a key has a smart-card interface but the smart-card service
  lists no reader for it, usually because the system's smart-card driver
  doesn't know the model yet, `doctor` says so and the app adds a line to the
  key's Overview page. ([#215])
- **`openpgp info` notices a key whose fingerprint is missing.** It now
  reads each slot's public key (no PIN) and, when a slot holds a key but no
  fingerprint, says `(none), but a key is present`; the app's OpenPGP card
  says the same, `(none), but a key is present`. `--json` gains
  `key_present_sig`, `key_present_dec` and `key_present_aut` (true, or
  `null` when the card doesn't tell). ([#215])
- **`piv --json info` says whether the PIN is verified and whether each slot
  holds a key.** New `pin_verified` (true/false) and, per slot, `key_present`
  (true, false, or `null` when the key can't tell). `piv info` and the app's
  PIV header now say "PIN verified" instead of "PIN accepted", matching
  `openpgp pin verify`. ([#215])
- **`piv info` lists the retired key slots that are in use.** Slots 82–95
  show after the standard four when they hold a certificate or a key, in
  the text output and in `--json`'s `slots`. ([#221])

### Changed
- **No PIN or touch policy for new PIV keys on a Nitrokey 3.** On firmware
  newer than 1.8.3, up to 1.9.1, `piv key generate` and the app's Generate
  dialog used to warn about a PIN or touch policy and then send it.
  According to Nitrokey's published PIV source, this firmware doesn't apply
  those settings and has nowhere to store one; its PIN rule is fixed per
  slot and it has no touch requirement. keyroost now
  refuses a policy other than `default` on these keys, as it already did on
  older firmware; `--force` in the CLI or Enable Anyway in the app still
  sends it. ([#174])
- **Authenticator codes come back in one read.** The Authenticator tab now
  asks the key for every code at once, as Yubico Authenticator does,
  instead of one account at a time. On a key with accounts that require a
  touch, the tab no longer waits about 15 seconds per such account before
  showing anything: those accounts show **Read code** straight away. A
  Nitrokey 3 has no all-codes command, so keyroost asks for its account
  list with each account's touch setting instead, with the same result.
  Accounts with a period other than 30 seconds are still read one by one.
  ([#199])
- **One Refresh button.** The top bar's Refresh is now the only one: the
  sidebar's rescan icon, the Refresh on the Authenticator, PIV and OTP
  tabs, OpenPGP's Read status, FIDO2's Reload and Load buttons and the
  Molto2's Refresh slots are gone. Refresh reads again whatever is open,
  down to the passkey, fingerprint or storage list. The OpenPGP card and the
  fingerprint list now read themselves when you open them, like the other
  tabs. The New CHUID dialog's button for a new random ID is now labeled
  "New GUID". ([#200])
- **An unplugged key is selected again when it comes back.** Unplugging the
  selected key used to leave whichever key took its place selected after
  you plugged it back in. The app now selects the key again, unless you
  picked another one meanwhile. It recognizes the key by its serial or the
  name stored on it, never by a guess. ([#202])
- **A certificate can go into a PIV slot that has no key yet, in the app too.**
  The app used to disable Import certificate for such a slot; it now allows
  it, as the CLI and other tools do, and both say the certificate won't work
  until a matching key is put in the slot. ([#215])
- **Nitrokey is spelled Nitrokey.** `piv info` and the app's PIV header wrote
  "NitroKey"; `piv --json info` now reports
  `"applet_fingerprint": "Trussed::Nitrokey"` (was `Trussed::NitroKey`).
  ([#215])
- **A code you touched the key for no longer vanishes at the 30-second
  mark.** In the app, **Read code** on an account that requires a touch now
  works out the code for 10 seconds ahead, as Yubico Authenticator does, and
  the code stays on screen until its own 30 seconds are up. When that is the
  next 30 seconds, the code shows in gray with **wait 4s** counting down
  until it starts, and its **?** explains why. ([#217])
- **A FIDO2 key with no serial number can be reset when it is the only key
  plugged in.** The app refused such a key outright. The app and
  `keyroostctl` now follow one rule: with other keys connected, the reset
  is refused before anything is wiped, naming the keys to unplug. ([#221])
- **A banner asks for the touch the key is waiting for.** While a job waits
  for a touch, the request shows in a banner at the top of the window
  instead of as small gray text in the top bar. ([#221])
- **The idle lock also wipes secrets left in a form.** A PIN, PUK, password,
  passphrase, management key or seed typed into any masked box and not yet
  used now starts the idle clock, and the box is emptied when it runs out.
  ([#223])

### Fixed
- **Token2 OTP works over USB on PIN+ keys with firmware 2.1.** On these
  keys `otp list`, the app's On-device OTP tab and every other OTP command
  failed with "unexpected status word 0x0105": the key's FIDO interface
  didn't accept the way keyroost framed OTP commands. keyroost now sends
  them through the CTAPHID vendor command Token2 documented, and keeps the
  earlier framing for keys that don't answer it. A code that needs a touch
  says "touch your key" when the key asks for one. ([#155])
- **`otp info` and `otp reset` work over USB on the same keys.** Both failed
  with "unexpected status word 0x6FFB": the key rejects the short form
  keyroost sent them in over USB. They now go out in the form Token2's
  protocol document and reference client use; over a smart-card reader
  nothing changes. ([#155])
- **A PIV slot holding only a certificate no longer reads as holding a
  key.** In the app, generating a key into such a slot warned that it
  "destroys the existing key", and Move key and Delete key were offered
  for it. It now reads "certificate present, no key", and generating or
  moving a key into it notes that the certificate stays. Retired slots now
  show their certificates too. `keyroostctl piv info` adds ", no key" to
  such a slot's line. ([#174])
- **TrustKey keys are named TrustKey.** Keys with USB vendor ID 0x311F
  (registered to eWBM, whose keys now sell as TrustKey) showed as "Security
  key" in 0.14.0; they now show as TrustKey, with the model from the key
  (for example "TrustKey B210H"). Reported by @Ephemera42. ([#195])
- **U2F-only keys are labeled U2F.** A key whose FIDO side speaks only U2F,
  such as the YubiKey NEO, was labeled FIDO2. keyroost now asks each key's
  FIDO interface which protocol it speaks and labels it U2F when that is all
  it does, in `keyroostctl list` (and `list --json`) and in the app, which
  no longer offers a FIDO2 tab or a FIDO2 reset step for it. ([#201])
- **Piping a secret in Windows PowerShell 5.1 works.** `"SEED" |
  keyroostctl oath add NAME --seed stdin` failed there with "the seed is
  not valid base32 (invalid character in input)": PowerShell 5.1 can start
  piped text with an invisible byte-order mark, two of them when the
  console also uses UTF-8, which keyroost took as part of the seed.
  Byte-order marks at the start of stdin are now ignored for every secret
  read from it. ([#203])
- **The key's model and firmware stay in the header.** After a rescan
  (Refresh, or plugging a key in or out) the selected key's header dropped
  back from, for example, "YubiKey 5 Series with NFC · fw 5.7.4" to
  "YubiKey". It now keeps them. ([#204])
- **Files saved by Windows tools import.** An Aegis or 2FAS export or an
  otpauth:// list that starts with a byte-order mark (as Windows PowerShell
  5.1's `Out-File -Encoding utf8` and some editors write) was refused, or
  lost its first account; UTF-16 text (what PowerShell 5.1's `>` writes)
  wasn't read at all. Both now import, in the app and with
  `keyroostctl … import`. ([#205])
- **Authenticator works on the Nitrokey 3.** On current Nitrokey 3 firmware
  every Authenticator command failed with "conditions of use not satisfied":
  the key holds a reply back until it is asked for with the standard
  GET RESPONSE command, and keyroost only knew the YubiKey's way of asking.
  keyroost now asks each key the way it expects, so accounts can be listed,
  added, read and deleted. A Nitrokey 3 asks for a touch to reset its
  Authenticator app, to delete any account, and to save or read one that
  requires a touch. The CLI and the app say so, and a missed touch gets a
  message that says to try again and touch the key. ([#208])
- **Authenticator codes no longer drop out while a browser is open.** A
  browser checking the key for smart-card certificates could slip its own
  commands in between keyroost's, and the app then showed **Read code** on
  ordinary accounts. keyroost now keeps the key to itself for the length of
  each Authenticator read or change. ([#208])
- **The Nitrokey 3's firmware version shows in the app.** The key header
  showed "fw 0.0.0", the placeholder the key's FIDO side reports; it now
  shows the version from the key's admin application. ([#208])
- **Device scans ask a key for its identity once.** On macOS, the app asked
  a Yubico key for its serial number over the FIDO connection on every
  device scan, so a key that doesn't support that question (such as the
  YubiKey NEO) was asked again and again, and debug logs filled with the
  same two lines. keyroost now keeps the answer for as long as the key stays
  plugged in, wherever that can't be mistaken for a different key.
  ([#211])
- **PIV, OpenPGP and OATH reads work on a YubiKey NEO.** On macOS, reading
  a YubiKey NEO's PIV, OpenPGP or OATH applet failed with "no Smart Card is
  currently in the device" or "an attempt was made to end a non-existent
  transaction", while ykman read the same key. The reads failed right after
  keyroost asked the NEO's FIDO side for its serial number, a question it
  does not answer. keyroost no longer asks it. As an added safeguard,
  keyroost also waits up to three seconds for a card that has just reset and
  opens the session once more, before sending anything that could change the
  key. ([#211])
- **A FIDO key that doesn't answer properly shows as FIDO2?.** A key that
  opened but gave no proper answer to keyroost's first question used to
  show as FIDO2 and get a name read and a FIDO2 reset step; it now shows
  FIDO2? and gets neither until it answers. A key keyroost can't open at
  all keeps FIDO2 as before, and a failed question is asked again on the
  next scan. A key reached only through a smart-card reader now shows
  FIDO2? unless its FIDO applet reports FIDO2. ([#215])
- **`doctor` no longer calls a Token2 FIDO key's reader a Molto2.** It tagged
  every reader with "TOKEN2" in its name "(Molto2)"; only a Molto2's reader
  gets the tag now. ([#216])
- **A Nitrokey 3 is called "Nitrokey 3", not "3".** The CLI's target line,
  the app's key header and the lists that ask which key to use showed only
  "3". ([#216])
- **Without administrator rights on Windows, "no key" errors say why.**
  `fido info` and `otp --transport hid` said no key was connected when a
  FIDO key was plugged in. Windows only lets a program running as
  administrator open a key's FIDO USB side, and the error now says so, as
  `list` already did. ([#216])
- **`fido info --reader` and `fido reset --reader` name the reader they use.**
  The target line showed the key's USB path instead. `fido reset --reader`
  now checks the reader before asking to confirm: it gives the same error
  as `fido info --reader` when the reader's card has no FIDO side, and on
  Windows without administrator rights it says administrator rights are
  needed. ([#217])
- **`fido info` shows a Nitrokey 3's firmware version.** It printed 0.0.0,
  the number the key gives over USB; keyroost now reads the real version
  from the key, as the app already did. ([#217])
- **`otp code` asks for a touch through a smart-card reader too.** For an
  entry saved with `--touch`, it waited silently for the touch when it went
  through the key's reader; it now says to touch the key, as it does over
  USB. ([#217])
- **The On-device OTP tab fits a narrow window.** The add-entry form broke
  its labels mid-word, the secret field ran past the edge, and the tab's
  buttons covered its title. The buttons now move under the title when there
  is no room. ([#217])
- **Importing from a .p12 file names the key by its certificate.** A file
  exported by Windows showed an internal name such as `te-` followed by a
  long code; the import now shows the certificate's name instead. ([#217])
- **A factory reset asks for the touch that erasing OTP entries needs.** On a
  Token2 key the reset's OTP step waited silently for a button press and then
  failed with "timed out waiting for a button press on the key". The app's
  Factory reset card now says to touch the key while the reset runs, and
  `keyroostctl factory-reset` prints a touch line over a smart-card reader
  too. ([#218])
- **Forced PIN changes no longer block unlocking.** When a FIDO key
  requires a PIN change, the app opens the change-PIN form instead of failing
  with a PIN policy error. After the change, the key can be unlocked with the
  new PIN. CLI commands that need a PIN token now ask for a PIN change first
  instead of reporting a misleading new-PIN complexity error. Contributed by
  @Snrat. ([#220])
- **Idle locking clears every PIN draft.** Current, new, and confirmation
  PINs left in the change-PIN form are now wiped after inactivity, including
  when setting a first PIN. Contributed by @Snrat. ([#222])
- **"Always require user verification" is only offered on keys that report
  it.** Pressing Toggle on a key without the `alwaysUv` option failed with
  "authenticator returned CTAP2 status 0x02". The app now leaves the row
  out for such keys, and `fido config always-uv` says the key doesn't
  support it. Contributed by @Snrat. ([#224])
- **keyroost asks for a touch wherever the key needs one.** Over USB, the
  CLI and the app now say "touch your key" whenever the key reports it is
  waiting for a touch. Over a smart-card connection they say so up front
  where a touch is known or possible: `oath code` and `oath delete` on a
  touch account, the factory reset's OATH step, OpenPGP key import and
  backup restore, and Nitrokey 3 code replacement. The app's banner
  follows the key, and no longer appears while unlocking. ([#225])
- **The idle lock also closes what a typed password opened.** A file read
  for import, an OpenPGP key set made or read from a backup, and a .p12
  key now start the idle clock, and the dialog holding them closes when it
  runs out, saying why. The On-device OTP PIN boxes clear their typed
  history like every other secret box. ([#226])
- **Enterprise attestation, the minimum PIN length and a forced PIN change
  are offered only on keys that support them.** The app's FIDO2 Settings show those rows only
  where the key lists them, and `keyroostctl` refuses before asking for
  the PIN, as it already did for Always UV. ([#227])
- **Each key's firmware is shown the way its maker states it.** A Solo 2
  showed 2.3.196 for firmware 2.964, and a Token2 PIN+ showed 2.1.2; it now
  shows its release (for example "R3.4"), named from its serial number as
  Token2 publishes. In `keyroostctl fido info` and the app's key header;
  `fido --json info` gives `firmware: null` when a key doesn't say. ([#228])

### Security
- **Authenticator debug traces no longer show account names or codes.**
  `keyroostctl --debug` and the app's APDU trace showed the Authenticator's
  account names (in hex) and current codes when listing or reading codes.
  Those parts are now hidden, like seeds and passwords already were; the
  status words stay, which is what a bug report needs. Traces get pasted
  into public issues, and an account list tells which services someone
  uses. ([#206])
- **Newer elliptic-curve crates for P-256, P-384 and secp256k1.** The FIDO2
  PIN protocol, Token2 OTP seed encryption, OpenPGP key generation and
  signing, and the PIV self-test now use the RustCrypto elliptic-curve 0.14
  crates, which clears RUSTSEC-2026-0387, a timing-variability advisory for
  crypto-bigint 0.5. keyroost behaves the same. Building the libraries and
  the CLI from source now needs Rust 1.87 or newer (it was 1.85), because
  the fixed crypto-bigint and ctutils require it; the GUI still needs 1.92.
  ([#212])

## [0.14.0] - 2026-10-19

### Added
- **Create OpenPGP keys with a backup.** One step makes the signature,
  decryption and authentication keys, saves them to a passphrase-protected
  backup that GnuPG can read, writes your public key and a revocation
  certificate beside it, and loads the keys onto the card. In the app it is
  **Create keys with a backup…** on the OpenPGP card; on the command line,
  `keyroostctl openpgp key import --generate --backup FILE --name NAME`.
  ([#177])
- **Restore a backup** onto a new or reset card, from a keyroost backup or a
  GnuPG export (`keyroostctl openpgp key import --in FILE`).
- **Change expiry date** on a key set, signed with the card or the backup;
  *Never* removes the date. New keys default to three years, as in GnuPG.
- **More key types** for backups: RSA-2048/3072/4096, NIST P-256/384/521,
  secp256k1 and Curve 25519. Brainpool keys can still be made on the card.
- The old *Generate & import* option, which made a key on the computer and
  discarded it after loading, is gone; use *Create keys with a backup* or
  *Generate on-card*. On the command line, `openpgp key import --generate`
  now needs `--backup FILE` and `--name`, fills all three slots, and no
  longer takes `--slot`. The migration page has the details.

### Changed
- **Fewer round trips for PIV admin actions on keys without GET METADATA.**
  On keys that don't report their management key's algorithm, the app
  tried all four algorithms before every action that needs it. It now
  remembers the answer while the key stays plugged in and checks it with one
  request (two for AES-192), falling back to the full check whenever that
  could choose differently. ([#113])
- **A tidier, more adaptable window.** Theme, colorblind-friendly colors and
  text size now live in one Appearance menu, so the top bar no longer
  overlaps; the device list shrinks to a rail of key icons when space runs
  short; and every pane stays inside the window at large text sizes.
  Switching between OpenPGP keys, PIV slots and FIDO2 tabs now visibly
  lands, with the open tab joined to its card. ([#176])
- **The Windows app draws with DirectX 12.** It now opens on computers
  without OpenGL 2.0, such as virtual machines without 3D acceleration and
  some remote-desktop sessions, where it couldn't start before. If DirectX
  12 doesn't work, it falls back to OpenGL. Linux and macOS are unchanged.
  ([#185])
- **Less CPU while codes are counting down.** The app now redraws once a
  second for countdowns instead of twice, which matters most on machines
  without a GPU, where drawing is done in software. ([#190])
- **Every Refresh button does the same thing.** The top-bar Refresh, the
  sidebar's rescan icon and the Refresh on the Authenticator, PIV and OTP
  tabs now all look for keys again and then re-read the open tab of the
  selected key (on a Molto2, its slot list). Before, the top-bar Refresh
  only rescanned, so an account added with `keyroostctl` while the app was
  open didn't show up until the key was replugged or the app restarted.
  ([#190])

### Fixed
- **One row per key on Windows, even with two keys of the same make.** A key's
  FIDO interface and its smart-card reader are now recognized as one physical
  key from where both sit in the Windows device tree, the same evidence Linux
  gets from the USB bus. Neither the key nor the card is opened to find out.
  Under `--debug`, `keyroostctl list` prints what Windows reported for each
  key (`devtree` lines). Library users: `usb_bus` / `usb_address` on
  `HidDevice`, `ReaderProbe` and `YubiKeyCcid` are replaced by one
  `usb_device` field. Keys are also named properly there: "YubiKey" rather
  than "YubiKey 0", and "Solo 2" rather than "0". ([#51])
- **The Molto2's serial stays in the app's header.** After any device
  rescan (Refresh, or plugging in another key) the header showed "#—" and
  dropped the token's saved name until it was selected again. Reported by
  @janschmidt76. ([#125])
- **Windows: the zip runs on a fresh install, and says why when it can't.**
  The programs no longer need the Visual C++ runtime installed. If the
  computer's graphics can't run the app's window, a message explains it
  instead of the app silently closing. Without administrator rights,
  `keyroostctl list` and `doctor` now say when a FIDO key is plugged in
  but only an administrator can open it. ([#184])
- **macOS fixes from a macOS test.** `keyroostctl doctor` no longer reports
  every FIDO key as "No such file or directory" on macOS and Windows: it
  now opens each key the same way `fido info` does. Scanning a QR code from
  the screen on macOS covers every display instead of only the main one,
  and the screenshots go in a private temporary folder that is always
  removed afterwards. Smart-card readers plugged in after the app started
  are now noticed where the system doesn't announce new readers (as on
  macOS). The macOS builds now state their minimum: macOS 11 (Big Sur) or
  newer. The PIV page records that macOS's built-in PIV support read a
  compressed certificate. ([#188])
- **FIDO-only keys appear when plugged in.** The app noticed new keys only
  through their smart-card reader, so a key with just FIDO (no smart-card
  interface) showed up or disappeared only after Refresh. It now watches
  the FIDO key list too and rescans when a key comes or goes. ([#189])
- **Authenticator codes no longer go stale on screen.** The codes on the
  Authenticator tab and the Overview are read again when their time window
  rolls over, as the OTP tab already did; before, a code stayed up past its
  window while the countdown kept cycling. A code read on demand for a
  counter-based (HOTP) account stays shown across these refreshes. An
  account that requires a touch gets a **Read code** button instead of being
  re-read each window, so the key doesn't wait for a touch every 30 seconds
  and the other accounts' new codes aren't held back meanwhile. ([#190])
- **Authenticator accounts that require a touch can be added again.** The
  "require touch" setting was sent in a form YubiKeys refuse, so adding such
  an account (`oath add --touch`, or the touch option in the app) failed
  with `SW=6A80`. It now uses the layout the YubiKey accepts and the Trussed
  firmware source reads. ([#190])
- **Keys with USB vendor ID 0x311F are no longer labeled Feitian.** That ID
  was filed under Feitian by mistake, so other makers' keys showed the wrong
  brand; they now show the generic "Security key" until their maker is
  known. On Windows without administrator rights, a FIDO-only key's card
  showed its raw vendor ID instead of a name; it now uses the same names as
  everywhere else. Reported by @Ephemera42. ([#195])

### Security
- **The app locks itself after 5 minutes without input.** An unlocked FIDO
  key, a remembered Authenticator password or OTP PIN, and the codes on
  screen are cleared once the window has had no click, key press or scroll
  for 5 minutes, and the pane says so. A running operation is never
  interrupted. Copied codes and generated management keys are now marked to
  stay out of clipboard history on macOS, Windows and X11. ([#190])

## [0.13.0] - 2026-10-10

### Added
- **Swissbit iShield serial, name and firmware.** keyroost reads the serial,
  device name and firmware version of Swissbit iShield Key 1 and 2 cards from
  their own management applications, and shows them in `piv info` and the
  GUI. Contributed by @episource. ([#163])
- **X.509 key usage for PIV certificates and requests.** Self-signed
  certificates and CSRs carry a keyUsage extension, in the GUI and with
  `piv cert generate` / `piv cert request --key-usage`. By default it is
  the slot's standard PIV usage, marked critical; `--key-usage undefined`
  (or "Undefined" in the GUI) writes none. Contributed by @episource.
  ([#164])
- **Shell completion for saved key names.** `keyroostctl completions
  <shell>` now prints a short script that asks keyroostctl for
  suggestions, so `--device` completes the names you saved. The AUR and
  Homebrew packages install completions and man pages. ([#165])
- **`--encoding` for seeds and Molto2 customer keys.** Seeds are base32
  unless `--encoding hex` (`oath add`, `otp add`, `otp button set`,
  `molto seed set`, `prog seed set`). A new Molto2 customer key is hex unless
  `--encoding ascii`; the current key's encoding is
  `--customer-key-encoding`. ([#165])
- **Numbered `list` and `list --json`.** `list` numbers each key (sorted by
  serial, so a number can change when keys are added or removed), and
  `--json list` prints `{"keys": [...]}`, one row per key with the exact
  `--device` value that selects it. `list --device` shows just that key.
  ([#165])
- **Five short flags.** `-d` (`--device`), `-y` (`--yes`), `-o`
  (`--out`), `-i` (`--in`) and `-s` (`--slot`), with the same meaning on
  every command. ([#165])
- **`fido blob clear --keep-name`** clears the large-blob storage but keeps
  the key's name ("Keep the key's name" in the app). Without it, the
  warning names the name that goes. `fido blob list` shows the name entry
  as `key name`, and `fido blob edit` points to `name set` instead of
  changing it. ([#166])
- **A key can carry its own name.** `keyroostctl name set NAME --store key`
  (or "On this key" in the app's naming dialog) writes the name into the
  key's FIDO2 large-blob storage, and every computer running keyroost shows
  it, without a PIN. Saving it needs the FIDO PIN; the name is visible to
  anyone who has the key. `name set` also renames, `name clear` removes a
  name wherever it is stored, and `name list` shows where each name lives.
  The entry's format is published with test vectors in
  `docs/PROTOCOL-device-label.md` so other tools can use it. If a key loses
  its name, `name list` and the app offer to write it back. Proposed by
  @token2. ([#166])
- **Two keys with the same name stay apart.** The first key this computer
  saw with a name keeps it, and `--device NAME` always means that key.
  Another key carrying the same name shows as "Name (1234)", the last four
  characters of its serial, for display only; select it by its `list`
  number or `serial:…`. ([#166])
- **Import authenticator codes into any key that stores them.** `oath
  import` adds every code in an Aegis (plain or encrypted), 2FAS,
  `otpauth://` list or QR export to a YubiKey, Solo 2 or Nitrokey 3, and
  `otp import` to a Token2 key's OTP storage. In the GUI, drop the file on
  the window or click "Import file…" in the Authenticator, On-device OTP or
  Molto2 view; the "Import authenticator codes" dialog works for every key
  that stores codes. keyroost reads the key first and previews each entry:
  a code whose name is already on the key is skipped (`--replace`
  replaces it), and one the key can't store is listed with the reason.
  `--dry-run` writes nothing. It asks once, writes one code at a time, and
  stops at the first error with a report of what was added. ([#170])
- **Solo 2 names are capped at 127 bytes.** `oath add`, `oath import` and
  the GUI refuse a longer Solo 2 name before sending it: a 128-byte name
  made the key stop responding until it was unplugged. ([#170])
- **YubiKey 4 prefix names.** On YubiKey 4 firmware 4.0 to 4.3.4, `oath
  add`, `oath import` and the GUI refuse a name that is the start of
  another name already on the key, following the same rule as Yubico's
  `ykman`. ([#170])
- **The AppImage is GPG-signed.** Each release's AppImage carries an
  embedded signature from a dedicated signing key; its fingerprint is in
  SECURITY.md and the README, which also explain how to check it.
  AppImageUpdate-based updaters (appimageupdatetool, AppImageLauncher)
  now refuse an update signed by a different key. Users updating an
  unsigned AppImage (v0.12.x or earlier) with these tools download this
  release by hand once. ([#171])

### Changed
- **Always-UV is set, not toggled.** `fido config always-uv enable` and
  `fido config always-uv disable` replace the `fido always-uv` toggle, so
  a script always knows the state it leaves. Each one does nothing, and
  says so, when the key is already in that state. ([#165])
- **Commands are grouped by what they act on, in separate words.**
  `piv pin change`, `piv key generate`, `piv cert import`, `openpgp pin
  change --admin`, `openpgp key show`, `oath password set`, `otp pin set`,
  `otp button set`, `fido credential list`, `fido fingerprint add`, `fido
  config always-uv enable`, `fido pin min-length set`, `fido blob …` (was
  `large-blob`), `fido ssh …` (was `ssh-cert`), `molto sync`, `molto
  import --in`, and `name set|list|clear` (was `key-name`). `piv info`,
  `openpgp info` and `otp info` replace `piv status`, `openpgp status` and
  `otp config`; `otp get` is `otp code`, `otp erase-all` is `otp reset`,
  and `otp fp-list` / `otp unlock-list` are `otp list --unlock
  fingerprint` / `--unlock auto` (`--pin-only` is `--unlock pin`, the
  default). An old name is refused with an error naming the new one. The
  migration page lists every change. ([#165])
- **Destructive commands ask first.** In a terminal they show a y/N question
  naming the key; in a script they need `--yes` (`-y`). A command whose
  PIN or seed is piped in on stdin also needs `--yes`. This now also
  covers replacing or deleting what the computer can't restore: `oath
  delete`, `otp delete`, `otp button set` (when a seed is already set) and
  `otp button clear`, `fido credential delete` and `fido fingerprint
  delete`, `molto seed set` and `molto import` on used slots, `molto
  customer-key change`, `prog seed set` and `prog config set`, and on PIV
  `retries set`
  (which also resets the PIN and PUK to their factory defaults) and,
  unless the slot is known to be empty, `key generate`, `cert import`, `cert generate` and
  `--generate-key`. If the question was shown, keyroost checks it is
  still the same key before acting. `factory-reset` asks you to type
  `reset`, and `otp interface` reads its phrase from the terminal only.
  ([#165])
- **`piv cert export` writes PEM by default.** `piv cert export --slot 9a`
  at a terminal now prints the certificate instead of refusing. Add
  `--format der` for the raw DER bytes `piv export-cert` wrote before.
  ([#165])
- **Flags renamed to match.** `molto` commands take `--slot` (`-s`) in
  place of `-p` / `--profile` (Token2 calls slots profiles), and `molto
  config set` and `prog config set` take `--period` in place of
  `--time-step` (same values). `piv cert import` and `molto import` read
  `--in FILE` (`-i`), and `piv cert export`, `cert request`, `cert
  generate` and `key generate` write `--out FILE` (`-o`), in place of
  `--file` and `--save-pubkey`; `--load-pubkey` is `--pubkey-in`, and
  with `--generate-key`, `--save-pubkey` is `--pubkey-out`. `piv mgmt-key
  change` takes `--algorithm` (was `--new-algorithm`). The item a command
  acts on is an argument: `fido credential delete ID`, `fido fingerprint
  rename ID NAME`, `fido fingerprint delete ID` and `fido fingerprint add
  NAME` (were `--cred-id`, `--template-id` and `--name`). `fido ssh
  export` takes the SSH credential's RP ID as `--rp` (was
  `--credential`). `fido blob export` takes the output file as `--out
  FILE` instead of a second argument: `keyroostctl fido blob export 1 -o
  entry.bin`. An old flag is refused with an error naming the new one.
  ([#165])
- **Clearer `--help`.** Every flag and argument has a description.
  Commands that erase or replace something end their first line with one
  marker, such as "Irreversible: asks first (`--yes` to skip)", and that
  now includes commands that replace a key or seed (`piv key generate`,
  `molto seed set`, `otp button set` and others), `piv retries set`
  (which says it also resets the PIN and PUK) and `otp interface`. `piv
  cert request --generate-key` replaces the slot's key and asks first.
  The top-level description covers every command group, and `--debug`,
  `--device` and `--json` are listed under "Global options" after a
  command's own flags. Two messages now say "canceled" (was
  "cancelled"). ([#165])
- **A hidden prompt for PINs, passwords, keys and seeds.** Every secret
  comes from `env:NAME`, from `stdin` (one line), or, with no flag and a
  terminal present, from a prompt that doesn't show what you type, like
  `sudo` or `ssh`. `stdin` typed at a terminal is hidden too. The Molto2
  and `prog` seeds and the new Molto2 customer key now prompt as well
  (`--encoding` says how they are written). New PINs, passwords and keys
  typed at the prompt are asked twice and must match; seeds and URIs are
  asked once. A script with no source is refused with an error naming
  the flag. Hex and base32 values lose surrounding spaces; PINs and
  passwords are kept exactly. After you type a secret at the prompt,
  keyroost checks it is still the same key before acting. In Git Bash
  (mintty) on Windows the prompt needs a real console: run `winpty
  keyroostctl …` or use `env:NAME`. The prompt uses the new `rpassword`
  dependency. ([#165])
- **One JSON shape.** `--json` output is always one object. Lists sit under
  a named key: `keys` for the overview and `list`, `accounts` for `oath
  list` and `otp list`. Every field is present, `null` when unknown. Each
  idea has one name and type: `serial` is a string, PIV `slot` is the
  `--slot` value (`"9a"`) with `slot_name` beside it, `molto info` reports
  `utc_time`, `molto list` reports `algorithm` (`"sha1"`), `period` and
  `digits`, `oath list` and `otp list` spell `algorithm` the same way
  (`"sha1"`), PIN retries are `user_pin_retries`, `pin_retries` and so on,
  accounts have a `type`, and the overview says `capabilities`. The
  migration page lists every field. ([#165])
- **Every command finds its key the same way.** A lone key is used
  automatically. With several, a terminal shows a numbered list to pick
  from (now on every platform); a script gets a refusal that lists the
  `--device` value for each key. No command takes "the first key found"
  any more. `--device` takes a name, a serial or a `list` number
  (`name:`, `serial:` or `list:` forces which); a Molto2 answers to either
  serial keyroost shows for it, the one in `list` or the one `molto info`
  prints. `--device` with `--reader` or `--path` is refused, and so is
  `--device` on commands that touch no key. `--reader` and `--path` skip
  the capability check, and a value that matches no detected key is used
  as typed. ([#165])
- **One message style.** Messages are sentences (`Seed written to slot
  #5.`), warnings and notes start with `warning:` / `note:` on stderr (the
  import preview keeps its own `Note:` lines), `fido info`, `molto info` and `prog info` each line their fields up
  block by block, and Molto2 messages say "slot" where they said "profile".
  ([#165])
- **One word per action, and every command ends in one.** The same job
  has the same word in every group: `fido pin status` (was `pin-retries`)
  and `fido credential status` (was `creds-metadata`) show state like
  `otp pin status`; `fido blob show` (was `large-blob get`) prints one
  entry; `fido ssh export` (was `ssh-cert extract`) saves a file like the
  other `export` commands; `otp button clear` (was `delete-button-hotp`)
  is the opposite of `set`; `molto list` (was `molto slots`) lists like
  every other group. Writes end in an action word: `molto seed set`,
  `molto title set`, `molto config set`, `prog seed set`, `prog config
  set`, `fido pin min-length set` (was `set-min-pin`) and `molto
  customer-key change`. `molto title --slot N` without `set` only shows
  the slot's title. An old name is refused with an error naming the new
  one, and nothing typed after it is repeated. ([#165])
- **An existing output file is never replaced silently.** `piv cert
  export`, `cert request`, `cert generate` and `key generate --out`,
  `openpgp sign`, `decrypt` and `authenticate`, and `fido blob export`
  and `fido ssh export` ask "overwrite? [y/N]" at a terminal when the
  output file exists, and refuse in a script unless `--overwrite` is
  given. A directory as the output is refused before the key is touched,
  and so is a symlink for the `openpgp` outputs. `--overwrite` only
  covers the local file; `--yes` still confirms what happens on the key.
  ([#165])
- **Out-of-range values exit 2.** A number outside its range (`oath add
  --digits 9`, Molto2 slot 100, a retry count of 0) is a usage error that
  exits 2, like any other mistyped argument. Some of them used to exit 1.
  ([#165])
- **Reset credentials are read before the reset starts.** `piv reset`
  and `factory-reset` read their `--mgmt-key` or `--pin` before anything
  is reset, even on a card that turns out not to need it. An unset
  `env:NAME` variable is now an error up front, where before it could be
  ignored. ([#165])
- **FIDO2 reset waits for the replug.** `fido reset` on a USB key and the
  FIDO2 step of `factory-reset` now ask you to unplug the key and plug it
  back in (within 60 seconds), check it is the same key, then ask for a
  touch. There is no Enter to press. `factory-reset` ends with "N wiped,
  M skipped, K failed" and exits with an error if any step was skipped
  or failed. ([#165])
- **One flag per secret; its value says where the secret comes from.**
  `--pin env:NAME` reads an environment variable and `--pin stdin` reads
  one line, replacing `--pin-env NAME` and `--pin-stdin`. The same goes
  for `--new-pin`, `--puk`, `--new-puk`, `--admin-pin`, `--mgmt-key`
  (which also takes `default`), `--new-mgmt-key`, `--password`,
  `--new-password`, `--seed`, `--customer-key`, `--new-customer-key` and
  `--uri`. The `--old-…` flags are now the plain name: `--pin` is the
  current PIN and `--new-pin` the new one. `oath add --secret-env` is
  `--seed env:NAME`, `openpgp verify --pin admin` is `openpgp pin verify
  --admin`, and `otp change-pin --current-env` / `--new-env` are `otp pin
  change --pin env:NAME --new-pin env:NAME`. A secret typed as the value
  itself (`--pin 123456`) is refused with exit 2 and never shown. An old
  flag is refused with an error naming the new one. ([#165])
- **`fido ssh export` takes `--overwrite`, not `--force`.** The old
  `ssh-cert extract --force` is gone. ([#165])
- **Two secrets on stdin: the current one first.** When two flags read
  `stdin`, the current secret is the first line and the new one the
  second, and each flag's help says which line it reads. This changes the
  order for `oath password set` (current password, then new) and `piv
  mgmt-key change` (current key, then new); both read the new one first
  before. `otp add` and `oath add` read the seed first, then the PIN or
  password. On `molto`, `--customer-key stdin` is always the first line,
  before the seed, URI or new key. `prog seed set --seed stdin` reads one
  line, not all of stdin. ([#165])
- **The screen output is split: result on stdout, the rest on stderr.**
  Prompts, progress, "Authenticated.", the Molto2 serial and clock lines
  (except in `molto info`, where they are the result) and the "Wrote FILE"
  lines for saved files now go to stderr. So `keyroostctl molto list > slots.txt` saves just the
  table, and you still see the rest. ([#165])
- The Flatpak build's hash-pinned Python tools move to multidict 6.9.1
  (every artifact hash listed, as before). ([#166])
- **`keys.json` no longer holds serials.** Each name is stored with a
  salted fingerprint of its key, the salt kept in `keys.salt` beside it, so
  the file shows no serial and two computers' files can't be matched. An
  older `keys.json` converts the first time it is read; a backup of the old
  file is kept until the conversion succeeds, then removed. v0.12 can't
  read the converted file and shows keys unnamed; don't rename a key with
  v0.12 after upgrading, since that replaces the converted file and its
  names. If `keys.salt` is lost, set the names again; restoring the old
  salt doesn't bring them back.
  ([#166])
- Library API (`keyroost-ctap`): `LargeBlobArray`'s `entries` and
  `raw_array` fields are methods, `serialize_with_checksum` returns a
  `Result`, `extract_cert_from_entries` takes the array, and `EntryKind`
  gains `KeyName`, so an exhaustive `match` needs a new arm. New: the
  `device_label` module. ([#166])
- Library API (`keyroost-keyring`): `keys.json` format 2. `KeyEntry` is
  `KeyRecord` (a `fingerprint` and `stored` instead of `serial`); `add`,
  `by_name`, `by_serial`, `name_for`, `resolve`, `ConnectedKey`,
  `ResolveError` and `KeyringError::DuplicateSerial` are removed, and the
  save methods take `&mut self`. ([#166])
- Library API (`keyroost-resolve`): `Device` gains the public fields
  `naming` and `hid_serial`, `EnumerateOptions` gains `skip_key_names`, and
  `SelectError` gains `NameNotConnected`. New: the `names` module. The
  migration page lists every change. ([#166])
- **`molto import --file-password`.** An encrypted Aegis export's password
  now comes from `--file-password env:NAME` or `--file-password stdin`, the
  same flag `oath import` and `otp import` use (v0.12's `import-file
  --password-env` / `--password-stdin` are refused with an error naming
  it). ([#170])
- **The Molto2 "Bulk import" dialog is replaced.** "Import file…" in the
  Molto2 view, or a file dropped on the window, opens the shared "Import
  authenticator codes" dialog. Every dropped file is identified first: a
  certificate or key file gets a note saying where to import it, and any
  other file gets "keyroost can't import this file". ([#170])
- **`molto import --in` follows the shared import rules.** An entry the
  Molto2 can't store (for example a SHA-512 code or a 45-second period) is
  skipped with the reason instead of refusing the whole file, and entries
  past slot #99 are skipped. An entry with no issuer or account no longer
  takes a slot. The preview, the one question before writing (`--yes` in
  a script), the report and `--json` are the same as `oath import`.
  `--dry-run` shows which slots are in use when a Molto2 is connected
  (`--device` picks which one). ([#170])

### Fixed
- **One row per key on Windows and macOS.** Where the system reports no USB
  position, keyroost now asks each side of a key for the identity it reports
  (a YubiKey's serial, a Solo 2's ID, a Token2 key's serial) and joins the
  FIDO and smart-card halves into one row. The GUI sidebar and the CLI share
  this matching. With two keys of the same make, one that doesn't answer
  still shows as two rows. On Linux nothing changes. ([#51])
- **PIV slots say what keyroost can tell about the key.** `piv info` and the
  GUI used to call every slot without a certificate "empty". A slot without
  a certificate now reads "empty" when the card says it holds no key, "key
  present, no certificate" when the card confirms a key, and "no
  certificate (a key may be present)" when keyroost can't tell. keyroost
  can't tell on cards where it doesn't use GET METADATA's key type, and on
  cards whose GET METADATA answer neither names a key nor says there is
  none: slots on these cards that read "empty" before now read "no
  certificate (a key may be present)". On
  a YubiKey, a slot with a key but no certificate now reads "key present,
  no certificate" in the CLI (it said "empty"). JSON output is
  unchanged. ([#113])
- **`openpgp info` shows a Token2 key's full serial.** The OpenPGP card
  data holds only a shortened serial, so keyroost now reads the full one
  from the key's OTP applet, the way `piv info` has since 0.12.0 (built on
  @episource's PIV work). This covers the CLI, its JSON `serial` field and
  the GUI's OpenPGP view. ([#125])
- **`--debug` traces FIDO.** FIDO commands over USB now show their messages
  with `--debug`; before, only `KEYROOST_CTAP_DEBUG` did, and it still
  works. FIDO through a smart-card reader isn't traced. FIDO PIN exchanges
  (clientPIN, authenticatorConfig) are hidden except the retry count and
  key agreement, like PIV and OpenPGP PIN checks. Every group now shares one
  line format (`> label  bytes`), which is for people and may change.
  With the GUI's debug capture on, Token2 OTP trace lines (redacted as on
  stderr) now appear in its activity log. ([#165])
- **`prog` uses the token you choose.** It used to ignore `--device` and
  write to whichever reader was alone, programmable token or not. It now
  only considers programmable tokens and honors `--device` and
  `--reader`. ([#165])
- **Large-blob writes keep other tools' entries byte for byte.** Adding,
  editing or deleting an entry dropped fields keyroost didn't know from
  every other entry it wrote back. Entries keyroost doesn't change are now
  written back exactly as read, in order. ([#166])
- **One malformed large-blob element no longer hides the whole store.** An
  element not in the standard entry format is skipped and counted in `fido
  blob list` (and its JSON `skipped`), and kept unchanged by every write.
  ([#166])
- **Flatpak updates no longer fail on unsigned metadata.** The published
  repository's AppStream and `.Debug` refs went out unsigned, so Flatpak
  clients that verify them refused the metadata refresh. Every ref is now
  signed, and publishing stops if one isn't. ([#167])
- **The Molto2 import dialog closes and says why adding is gray.** Close
  in the import dialog, and Cancel in the "Import to slot" dialog, did
  nothing; both now close the dialog, and closing either dialog by any
  route wipes the typed file password or pasted URI and drops the parsed
  entries (which carry seeds).
  When adding can't start, one line under the buttons now says why: the
  file is still loading, or the Molto2 isn't open or unlocked yet (with
  an Authenticate button right there, and a failed attempt is reported in
  that line too). ([#170])
- **Codes for OATH entries named `60/…` use their period.** `oath code`
  (without `--period`) and the GUI computed them at 30 seconds, so they
  were wrong. `--period` now defaults to the name's `period/` prefix, and
  the GUI shows the period next to the code. ([#170])
- **`oath code --period 0` is a usage error.** It crashed; it is now
  refused with exit 2. ([#170])

### Removed
- **`--list-readers` is gone.** `keyroostctl list` shows the smart-card
  readers along with every other connected key. ([#165])
- **No secret on the command line.** The flags that took a secret as a
  plain argument are gone, because the command line ends up in shell
  history and `ps`: `molto --key` / `--key-ascii` (use `--customer-key
  env:NAME`, with `--customer-key-encoding ascii` for an ASCII key),
  `molto seed` and `prog seed` `--hex` / `--base32` (use `molto seed set`
  or `prog seed set` with `--seed env:NAME` or `--seed stdin`, and
  `--encoding hex` for hex), and `molto customer-key --hex` / `--ascii`
  (use `molto customer-key change --new-customer-key`). `molto
  import` no longer takes the `otpauth://` URI as an argument: use `--uri
  env:NAME`, `--uri stdin`, `--qr IMAGE`, or the prompt. Each removed flag
  is refused with an error that names its replacement and doesn't repeat
  the value. ([#165])

### Security
- **Errors don't repeat a secret.** A secret typed where its source goes
  (`--pin 123456`, `--pin123456`, `--seed=JBSWY3DP`), a stray value after
  a source, a literal `otpauth://` URI or a removed flag's value is
  refused without being printed, and an error about an `env:NAME` source
  names the flag, not the variable, in case the secret was typed where the
  name goes. ([#165])

## [0.12.0] - 2026-10-04

### Added
- **PIV applet fingerprinting and per-key feature support.** keyroost now
  identifies which PIV implementation a card runs (YubiKey, Token2, Nitrokey,
  uTrust, HID Crescendo, Authentrend, OpenFIPS201 and others) from its ATR,
  SELECT response and a few AID probes, and shows it in `piv status` and the
  GUI's status line, with the device firmware next to the applet version
  where it differs. A built-in list says which vendor extensions (move and
  delete key, reset, key types, PIN and touch policies) each applet supports.
  Unknown applets keep every control, with a warning; a feature the list
  marks unsupported is greyed with the reason on hover, and the GUI's
  **Enable Anyway** line at the bottom of the PIV pane turns those back on
  for that key until the app closes. In the CLI, `--force` does the same.
  Contributed by @episource. ([#128])
- **More PIV key and certificate options.** ECC P-521 keys
  (`--algorithm eccp521`) and SHA-512 signatures; `--years`, `--months` and
  `--days` combine for certificate and CHUID validity (default: one calendar
  year), with matching GUI fields; `--mgmt-key-default` uses the card's
  factory management key. ([#128])
- **PIN-protected management key.** `piv change-management-key
  --allow-pin-unlock` (GUI: "Allow PIN unlock") stores the management key so
  the PIN alone unlocks management, and the GUI can authenticate with the PIN.
  The Change management key dialog can generate a random key and copy it; the
  clipboard is cleared after 45 seconds. ([#128])
- **HID Crescendo management.** Management-key authentication and rotation,
  Delete key, the serial number, and a whole-device factory reset, each
  through HID's own commands. ([#128])
- **Serial numbers match the device.** Token2 PIV and OpenPGP serials now show
  the number printed on the key, a Nitrokey shows its own serial, and serials
  too long for decimal display as hex. ([#128])
- **PIV certificates too large for a slot can be stored compressed.**
  keyroost can now write a certificate in the PIV standard's gzip form
  (CertInfo `0x01`, NIST SP 800-73-4). By default it stores certificates
  uncompressed and only compresses one the card refuses as too large (about
  3 KB on a YubiKey), saying so when it does. `piv import-cert` and
  `piv self-sign` take `--compress` / `--no-compress`, and the GUI's Import
  certificate and Self-signed dialogs have a matching Compression choice.
  Every compressed write is read back and checked. `piv status` and the GUI
  show which certificates are stored compressed. ykman, OpenSC and, in a
  community test on Windows 11, Windows' built-in smart-card driver read
  them; macOS's built-in PIV support has not been verified yet (testers
  welcome in [#152]). ([#154])
- **"Enable Anyway" and `--force` also cover keyroost's own reads.** GET
  METADATA and ATTEST, which keyroost skips on an applet listed without them,
  are sent too, so key details and attestation still show if the list is out
  of date. Every skipped or overridden read leaves a line in the `--debug`
  trace and the GUI activity log. ([#161])

### Changed
- **`piv reset` blocks the PIN and PUK itself where needed.** On a key listed
  as supporting reset, it now locks the PIN and then the PUK if the card asks
  for that before resetting; it used to fail unless both were already
  blocked. On a key that isn't listed, or with `--force` on one listed
  without reset, it sends one reset and locks nothing.
  Some cards also need the management key or PIN for reset, and keyroost asks
  for it. `factory-reset` now runs Token2 OTP before PIV, and on HID Crescendo
  uses the device-wide reset. ([#128])
- **PIV safety checks before writing.** `piv import-cert` refuses a
  certificate whose public key doesn't match the key in the slot;
  `generate-key` refuses a PIN or touch policy the card doesn't accept (unless
  `--force`) and clears the slot's old certificate; `self-sign` and
  `request-cert` refuse an X25519 slot before asking for the PIN. ([#128])
- **`piv status --json` reports `serial` as a string.** A serial can now be
  up to 128 bits, and a bare JSON number past 2^53 loses precision in most
  consumers, so it is a decimal string, or `0x`-hex when too long for
  decimal, matching the text output. It was a number through 0.11.0.
  New fields: `applet_fingerprint`, `applet_name`, `version_firmware`.
  ([#128])
- **PIV pane layout.** Every slot action stays visible and is greyed with a
  reason when it can't run; Import and Export certificate share a row; the
  pane is locked while a card command runs; PIN, PUK and management-key fields
  have a show/hide button. ([#128])

### Fixed
- **The AppImage runs on older Linux systems and minimal setups.** It is now
  built on Ubuntu 22.04, so it needs glibc 2.35 rather than 2.39, and it
  bundles the keyboard libraries (`libxkbcommon`, `libxkbcommon-x11`) the
  windowing layer loads at runtime; without them it crashed at startup on
  systems that lack `libxkbcommon-x11`. The Linux release tarball is built
  on Ubuntu 22.04 as well. ([#160])

## [0.11.0] - 2026-09-30

### Changed
- **Reset commands no longer guess which key to wipe.** With several matching
  keys connected and no selector, `molto reset`, `oath reset`,
  `openpgp reset` and `piv reset` now stop with an error that names
  `--device` and lists the candidates, instead of acting on the first one
  found (`molto reset`) or asking for `--reader`. Passing both `--reader` and
  `--device` to these commands, or to `fido reset`, is now an error instead of
  `--reader` silently winning. A single connected key still works without
  flags. Scripts that passed both flags, or relied on the first-found key,
  need to pass one selector.
- **`fido set-min-pin` and `fido enterprise-attestation` require `--yes`.**
  Both changes can only be undone by resetting the key, which wipes its
  credentials. Without `--yes` they refuse and send nothing to the key,
  matching the typed confirmation the app already asks for. Scripts that
  run them need to add `--yes`.

### Fixed
- **PIV reads now handle gzip-compressed certificates.** A PIV certificate
  object may hold its certificate gzip-compressed (the CertInfo byte
  `71 01 01`, part of the PIV standard); the tool that writes the certificate
  chooses this, and tools such as ykman do so on request. keyroost was
  handing the compressed bytes straight to the X.509 parser, which rejected
  them with "DER length field is implausibly large." `piv test` failed on
  such a slot before it even reached the PIN, and `export-cert` and the
  status pane's Subject-DN read had the same latent gap. keyroost now honours
  the CertInfo flag and inflates the certificate on read (size-capped), so
  `piv test`, `export-cert`, and the status pane read such a certificate
  correctly. The gzip checksum and length are verified on read, so a
  corrupted compressed certificate is reported as damaged rather than passed
  on. A compressed certificate whose data is damaged, or that would
  decompress past a 64 KiB cap, is reported as present but unreadable, with
  the reason: `export-cert` and `piv test` fail with that message rather than
  writing or parsing the raw bytes, and `piv status` (text, and `--json` via
  a new `cert_unreadable` field) and the GUI show the slot as holding an
  unreadable certificate, not as empty.
  Reported by @n0xena. ([#147])
- **PIV certificate imports that are too large now say so.** Importing a
  certificate of about 3 KB or more could fail with a raw PC/SC error
  ("An attempt was made to end a non-existent transaction") before the card
  answered, so the command-chaining fallback never ran. keyroost now retries
  such an import with command chaining. A certificate that fits (for
  example 3048 bytes on a YubiKey 5.7) imports. One the card refuses gets
  "the certificate (N bytes) is too large for <slot>", or "the card has no
  room left" when its storage is full. A refused import leaves the slot's
  existing certificate unchanged. ([#151])
- **`molto probe` no longer sends the keyless seed-delete instruction.** The
  hidden research command `keyroostctl molto probe --yes` sweeps the Molto2's
  instructions while skipping the ones that change the token, but its skip
  list missed `0xE6` (delete seed), which the token accepts without the
  customer key, so a probe could erase the seed in profile 0. It is now
  skipped like the other write instructions.
- **The AppImage starts on systems without the PC/SC library.** It used to
  refuse to launch when `libpcsclite.so.1` wasn't installed. It now still
  prefers the system's own library (needed to match the system's `pcscd`),
  and otherwise falls back to a bundled copy: keyroost starts, FIDO works,
  and the smart-card features report unavailable until `pcscd` is
  installed. ([#157])

## [0.10.0] - 2026-09-20

### Added
- **Nix flake.** The repository now builds as a flake: `keyroost` (the
  default package), `keyroostctl`, and a development shell, with the GUI's
  X11/Wayland libraries wired into the binary's rpath on Linux. Tested on
  x86_64 Linux. Contributed by @MakeShiftArtist. ([#109])
- **PIV slot key self-test.** `keyroostctl piv test --slot <slot>` (and a
  Test button in the GUI slot pane) proves a slot's private key works end to
  end: keyroost builds a fixed challenge from the slot certificate's public
  key, the card runs every operation the key type supports (decrypt for RSA,
  key agreement for P-256/P-384/X25519, sign for RSA/ECDSA/Ed25519), and the
  host verifies each result against that public key. Read-only on the card;
  needs the PIN unless the slot's PIN policy is "never". The verification
  side lives in a new `keyroost-pivtest` crate, which adds `p384`,
  `ed25519-dalek` and `x25519-dalek` (RustCrypto/dalek) to the tree.
  Contributed by @episource. ([#127])
- **Fingerprint unlock for Token2 Bio3 OTP.** On an R3.4 Bio3 key with a
  fingerprint enrolled, protected OTP codes can be released by a sensor touch
  as well as by the PIN. The CLI's `otp` group gains `fp-status`, `fp-enable`,
  `fp-disable`, `fp-list` (touch to unlock) and `unlock-list` (fingerprint
  first, PIN fallback; `--pin-only` forces the PIN), and the GUI's unlock
  prompt offers a touch button alongside the PIN field when fingerprint
  protection is on. Enrollment itself is done through the key's FIDO2
  fingerprint setup. Contributed by @token2. ([#130])

### Changed
- **`keyroost-token2otp`'s `PinFlag` is now `#[non_exhaustive]`.** It gained an
  `fp_enable` field this release; sealing the struct lets later firmware flags
  be added as fields without breaking library consumers, matching the other
  response types. Obtain a `PinFlag` from `PinFlag::parse` rather than a struct
  literal. ([#130])

### Fixed
- **PIV management-key authentication no longer assumes 3DES on cards that
  lack GET METADATA.** That Yubico extension is the only place a card reports
  its 9B key's algorithm, and applets without it (the Cryptnox OpenFIPS201
  variant, which ships with an AES key) were authenticated as 3DES and
  failed. When the extension is absent, keyroost now probes each algorithm
  with a bare GENERAL AUTHENTICATE witness request (no key material leaves
  the host), keeps the ones the card accepts, and narrows by the length of
  the key in hand; a 24-byte key that fits both 3DES and AES-192 still
  resolves to 3DES, so older YubiKeys behave as before. Applies to the CLI
  and the GUI alike, and `--debug` traces each probe's verdict. Contributed
  by @episource. ([#124])

### Security
- **The `--debug` trace no longer prints Token2 OTP PIN material.** The
  PIN-bearing commands — `SET_OTP_PIN`, `CHANGE_OTP_PIN`, and the PIN-carrying
  forms of `VERIFY_OTP_PIN` (a plain PIN verify, and the R3.4 Bio3
  fingerprint-protection toggle) — now have their request bodies length-redacted
  in the trace, the same as seed writes. The 1-byte `VERIFY` forms that carry no
  secret (lock, fingerprint verify) still show in full. ([#131])

## [0.9.0] - 2026-08-31

### Added
- **`piv self-sign` and `piv request-cert` can generate the key first.**
  `--generate-key` folds a fresh `generate-key` into the signing command,
  with the same `--algorithm`, `--pin-policy` and `--touch-policy` options,
  so cards without GET METADATA no longer need the `--save-pubkey` /
  `--load-pubkey` detour. Contributed by @episource. ([#116])
- **The activity log now covers PIV.** User actions and background reads
  are told apart, and with tracing on each APDU appears by name (for example
  `GET DATA 5FC105`) with the same redaction as `--debug`. The log can be
  detached into its own window and cleared. Contributed by @episource.
  ([#114])
- **OpenPGP keys in modern algorithms.** `openpgp generate-key --algorithm`
  (and the GUI's Generate dialog) can set a slot to Ed25519, X25519, NIST
  P-256/384/521, secp256k1, brainpool 256/384/512, or RSA 2048/3072/4096
  before generating; previously a slot could only ever produce its factory
  default (RSA-2048). The menu comes from the card's own algorithm list
  (`openpgp algorithms`, new) when it publishes one. `sign`/`authenticate`
  frame input correctly for ECC slots, `decrypt` performs ECDH on an ECDH
  slot, and `status` names the curve. Verified on a YubiKey 5.7. Requested
  by @mdedonno1337. ([#106])

- **OTP codes on a Token2 key can be put behind a PIN.** Keys running the
  R3.4 OTP applet can require a PIN before they hand out codes: `otp
  set-pin` protects a key, `otp verify` opens the read window,
  `otp change-pin` / `otp remove-pin` manage it, `otp pin-status` reports
  whether one is set and how many attempts remain, and `list` / `add` /
  `delete` take `--pin-env` or `--pin-stdin` to unlock in passing (the
  PIN is never an argument). The GUI's OTP pane grows an unlock prompt, a
  set/change/remove dialog and a "Lock now" action. The PIN travels
  encrypted under a per-connection ECDH session and is never sent in the
  clear. One thing to know before setting one: there is no reset — an
  exhausted retry counter is recoverable only by erasing every OTP entry
  on the key. Keys without the feature are unaffected:
  they answer the capability probe with "no such command" and everything
  behaves exactly as before. Contributed by @token2. ([#107])

### Changed
- **APDU errors now say what the status word means.** A failure like
  `SW=6A80` carries the ISO 7816 meaning in parentheses ("incorrect
  parameters in the command data field") when the word is a standard one;
  unrecognised words stay bare rather than guessed at. Applies to every
  applet's errors, CLI and GUI. Contributed by @episource. ([#118])
- Library API (`keyroost-openpgp`, `keyroost-transport`): `PublicKey` is now
  an enum (`Rsa` / `Ecc`), `OpenPgpSession::generate_key` takes an optional
  algorithm, `rsa_v4_fingerprint_from` is replaced by `v4_fingerprint`, and
  `OpenPgpStatus` carries each slot's raw algorithm attributes. The CLI's
  `openpgp status` (and its `--json` `*_algo` fields) now report
  `RSA-2048` / `EdDSA Ed25519` rather than the bare family name.
  `TransportError` gains two new variants — `OpenPgpSlotMismatch` (a
  requested algorithm that can't live in the requested slot) and
  `OpenPgpSlotNotRsa` (an RSA-only operation, i.e. key import, run against a
  slot that holds an ECC key) — so an exhaustive match over `TransportError`
  needs new arms.

- Library API (`keyroost-token2otp`): `EncryptError` gains `BadLength`,
  `BadCiphertext` and `BadAuthTag`, and `OtpError` gains
  `PinInvalidRetries`; in `keyroost-transport`, `OtpTransportError` gains
  `PinRequired` and `PinSessionMissing`. An exhaustive `match` over any of
  them needs new arms.
- Library API (`keyroost-piv`): `parse_version` is removed; the version is
  now kept as raw bytes and rendered with `format_version_bytes` ([#110]).
- **Public error enums and status structs are `#[non_exhaustive]`.** Adding
  a variant or a field to them is no longer a breaking change for library
  users; a one-time `_ =>` arm is needed in exhaustive matches.

### Fixed
- **The PIV pane's refresh no longer re-reads the same card objects.** It
  gathered each slot's key algorithm, certificate Subject DN and PIN/touch
  policy through separate transport calls, so every slot's certificate was
  fetched two or three times and GET METADATA twice. A new
  `PivSession::status_detailed` reads each slot's certificate object and
  GET METADATA exactly once and shares them across all three, roughly
  halving the refresh's APDU traffic. A slot whose certificate object
  carries no `70` TLV now reports as empty rather than "cert present",
  matching what `piv export-cert` already reported for it. `cert_len` in
  `piv status` (and `--json`) now reports the certificate's DER length
  rather than the card's object size, so it is a few bytes smaller than
  before. Contributed by @episource. ([#119])

- Library users enabling `keyroost-transport`'s `hidapi-backend` feature on
  its own no longer hit a compile error in `keyroost-ctap`: the feature now
  forwards to every crate that has a matching backend switch, not just
  `keyroost-hid`. CI builds every feature at once and never saw the partial
  combination; `cargo semver-checks` does, and did.
- **Certificate import and signing now work on contact (T=0) smart-card
  readers.** Large PIV commands were sent as extended-length APDUs first,
  with chaining only as a fallback after the card refused. A T=0 link cannot
  carry extended-length APDUs at all, and a Token2 PIN+ card on such a reader
  went silent instead of refusing — so the fallback never triggered and the
  command failed with a PC/SC "transaction failed" error. keyroost now reads
  the negotiated protocol and chains from the start on T=0; T=1 links are
  unchanged. Reported by @mdedonno1337, who also confirmed the chained path
  works on the affected card. ([#103])
- The PIV slot tabs wrap instead of overflowing in a narrow window.
  Contributed by @episource. ([#114])
- **PIV cards that answer GET VERSION with more than three bytes can now be
  managed.** The Swissbit iShield Key 2 Pro replies to the Yubico version
  extension with four bytes; keyroost rejected the reply and with it the
  card. The version is now kept as the card sent it and shown as-is (dotted
  for up to four bytes, hex beyond), and the firmware checks that gate
  YubiKey-specific behaviour compare the leading bytes exactly as before.
  Contributed by @episource. ([#110])
- **Identiv uTrust FIDO2 PIV cards can now be managed.** Their PIV applet
  answers management-key authentication without the final card-to-host
  proof, which keyroost treated as a failure. A card that accepts the
  host's proof but sends none of its own is now accepted; every card that
  does send its proof is verified exactly as before. The reduced assurance
  on such cards is reported in `--debug` output. Contributed by @episource.
  ([#104])

## [0.8.0] - 2026-08-24

**Why 0.8.0 and not 0.7.9:** this release changes the published library
crates in ways that require adjustments from code built on them — a new
`Instruction` variant in `keyroost-piv` and a new public field on
`keyroost-resolve`'s `Device` — so the version number says so, per semver.
Nothing else should be read into the jump: there is no 0.7.9, the 0.7
series simply ends here, only the latest release is ever maintained, and
the app itself is unaffected. Exact adjustments for library users are in
the [migration notes](https://framefilter.github.io/keyroost/migration.html).


### Added
- **`piv new-chuid`** (and a matching GUI action): write a fresh CHUID with a
  random GUID to a PIV card. Windows' PIV minidriver caches a card's contents
  keyed by the CHUID's GUID, so re-randomizing it makes Windows re-read a
  reprovisioned card. Encoding matches `yubico-piv-tool`'s template; the GUID
  comes from the OS's secure random source. Contributed by @episource. ([#102])
- **Nitrokey 3 PIV support.** keyroost's PIV surface now works on the
  Nitrokey 3, whose applet omits several Yubico extensions — the differences
  are detected from the card's own responses, never from its make or model.
  Verified end-to-end on a Nitrokey 3A NFC by the contributor, @episource,
  and cross-checked against Nitrokey's published firmware source. ([#102])

### Changed
- **keyroost now says when it couldn't check a capability instead of guessing
  silently.** A capability can be verified present (the device answered for
  it), absent, or *unverified* — offered without device evidence, which
  happens when a key is seen only over USB-HID and no smart-card reader was
  available to ask. Unverified capabilities behave exactly as before (the
  surface is offered and trying it gives the definite answer), but they are
  now rendered honestly: the GUI tab and capability pill gain a quiet "?"
  with an explanation, the CLI overview and `list` show e.g. `OTP?`, and the
  `--json` device output carries the state in a new `caps_unverified` field.
  This closes the gap behind the #82 → #95 OTP back-and-forth: the old
  present/absent-only model had to write "could not check" down as one or the
  other, giving a guess an authority it should never have had. ([#95])

- **`piv generate-key --pin-policy` / `--touch-policy` now explain
  themselves.** The flags have chosen the key-generation PIN/touch policy
  since PIV management landed, but `--help` never said what the values mean.
  It now spells out that `default` sends the standard PIV command every card
  accepts, and that the other values are a Yubico extension
  (firmware-dependent). Settles the CLI half of the [#97] review follow-ups —
  the GUI/CLI parity itself turned out to already exist. ([#97])

### Fixed
- **PIV commands with large payloads now work on cards that only speak
  short APDUs.** Signing and certificate import used extended-length APDUs
  unconditionally; cards that reject those (the Token2 PIN+ contact
  interface among them) now get the same bytes as a chained sequence of
  short commands instead. Cards that accept extended-length see identical
  traffic to before, pinned by tests. Contributed by @episource. ([#101])
- **The app now says which version it is.** The GUI shows a small version
  next to the wordmark in the top bar, and the AppImage embeds its version in
  the bundle metadata (`X-AppImage-Version`) so AppImage managers such as
  Gear Lever can display it. Previously the version was visible nowhere —
  not in the app, not in the AppImage. Reported by @alphazo. ([#98])

## [0.7.8] - 2026-08-13

### Fixed
- **The armed FIDO reset now survives Linux reusing the device path on
  replug.** The kernel hands a freed `/dev/hidrawN` name straight to the next
  device, so unplugging and replugging a key could bring it back on the exact
  path it had before — which the replug detector read as "never left", and the
  reset waited forever at the touch prompt. Reinsertion is now recognised by
  the USB attach itself (bus and device number, which advance on every plug),
  with the path kept as the fallback on macOS and Windows. Found, fixed and
  hardware-verified by first-time contributor @Algoritter — thank you! ([#96])
- **A replugged key identified by its card serial can re-match again.** The
  reinsertion check could only recognise a key by its USB serial or a YubiKey's
  CCID serial, so a key whose identity comes from a card applet (a Token2
  FIDO+PGP key, for instance) could arm the reset but never be recognised when
  it came back. The check now re-reads identity the same way it was captured
  when arming. Also part of [#96], same contributor.
- **A wrong OTP PIN now says so.** Four documented Token2 OTP status words were
  missing from keyroost's table, so a wrong PIN, a locked PIN, a
  function-not-available answer and a session-ordering fault all surfaced as
  "unexpected status word 0x…". All four are now named, with the locked-PIN
  message saying what recovery requires (a full OTP reset). ([#95])
- **A FIDO2 card in a smart-card reader can now actually be reset.** The reset
  flow assumed a USB key: it waited for an unplug, a replug, and a touch — none
  of which exist for a card sitting in a reader, so the dialog polled forever
  and the only way out was Cancel. A card now resets *in place*: keyroost
  power-cycles it in the reader (which opens the same brief after-power-up
  window a replug does) and sends the wipe immediately — no replug, no touch.
  The CLI gains the same route: `keyroostctl fido reset --yes --reader <name>`,
  and `keyroostctl factory-reset` picks it automatically for a card. USB keys
  keep the replug ceremony unchanged. ([#84])
- **A key that answers is no longer reported as a key that can't be reached.**
  Running an OTP command against a Token2 model that carries OTP over CCID said
  "the OTP applet is not reachable over HID or CCID — HID may be disabled on the
  key", which sent people to enable an interface that was already working: the
  key had completed a full USB-HID exchange and simply declined. These models
  ship with the HID channel disabled *by design*, because they have no
  HOTP-over-HID, so there was nothing on the key to enable. keyroost now tells
  the two apart — an applet that answers with a status word means the interface
  works and the key declined — and reports the failure that can actually be
  acted on: why the CCID path was unavailable (a stopped smart-card service, in
  the reported case), with the status word quoted and `--transport ccid`
  named. ([#95])
- **Token2 keys are offered the OTP surface again, whatever their product id.**
  v0.7.7 stopped listing OTP for product ids whose vendor function set omits it.
  Token2 has since confirmed that a function set omitting OTP does not mean the
  applet is absent: a key can carry OTP over CCID while its id reads FIDO+PGP.
  In practice v0.7.7 rarely got this wrong — when a card reader is present the
  capability comes from actually selecting the applet on the device, and that
  answer always wins — but with no reader, or no smart-card service running, the
  product id was the only evidence and a key could be shown without OTP it may
  well have. The guess is gone. A key that genuinely lacks the applet now
  reports which channel declined and what to do about it, instead of failing
  with a raw protocol error. ([#95])

## [0.7.7] - 2026-08-04

### Added
- **PIV move-key:** relocate a private key between slots (`keyroostctl piv
  move-key --from <slot> --to <slot>` and a GUI "Move key…" action), including
  the 20 Yubico retired key-management slots (82–95) for key archival /
  rotation. Non-destructive — refuses an occupied destination; the certificate
  stays in the source slot. Requires firmware 5.7+.
- **Extract an SSH certificate from a FIDO2 key** (`keyroostctl fido ssh-cert
  extract` and a GUI "Save certificate…" action): pulls the OpenSSH
  certificate a tool like `fido2-token` stored in a resident SSH credential's
  largeBlob and writes it as a standard `-cert.pub` file — so the cert travels
  with the key. Read/extract only; PIN required, no touch.
- **Factory reset (all applets):** one action — `keyroostctl factory-reset`
  and a card on the GUI device Overview tab — resets every resettable applet
  on a key (OATH, OpenPGP, PIV, Token2 OTP, then FIDO2). Uses only
  manufacturer-intended resets, and every applet that completes comes back in
  factory condition. Each step reports its own outcome, so anything that does
  not finish is named rather than folded into an overall "done". Per-applet
  resets remain available individually.
  **The name is reused, and that matters for old scripts.** `factory-reset`
  meant the Molto2 profile reset in 0.5.x and earlier, and became
  `molto reset` in 0.6.0. Both spellings are confirmed with `--yes`, so a
  script written against 0.5.x will *not* fail with "unknown subcommand" — it
  will run and wipe every applet on the key rather than only the Molto2
  profiles. Audit any script from that era for the exact string
  `keyroostctl factory-reset` and change it to `keyroostctl molto reset`.
  See `docs/migration.html`.

### Security
- **A forced PIV reset now refuses cards it could not put back together.**
  Wiping a PIV card whose PIN is unknown works by deliberately blocking the
  PIN and then the PUK, and only then sending a reset instruction — which is a
  vendor extension that standards-only PIV cards (issued corporate or
  government badges, for instance) do not implement. On such a card both
  counters were spent and the reset never arrived, leaving it recoverable only
  by whoever issued it. keyroost now checks for that extension *before*
  touching either counter and refuses outright.
- **Two connected keys can no longer be shown as one.** When a security key's
  USB position did not match any card reader, keyroost could guess that a
  reader belonging to a *different* key was its own, merging two physical keys
  into a single row. Card operations then went to one key while FIDO
  operations — PIN entry, credential deletion, reset — went to the other. Both
  the guess and the ordering bug that could still mispair a key have been
  fixed, and one key can no longer disappear from the list. On Windows and
  macOS, where the operating system does not report USB positions at all,
  keyroost now refuses to guess whenever two keys of the same make could each
  plausibly own the reader: it shows them separately rather than picking one.
  A key that is alone with its reader still pairs up as before.
- **An armed FIDO reset can no longer outlive what it was armed for.** If the
  key list failed to refresh, or arming was refused, an already-armed wipe
  could keep waiting invisibly and fire on the next replug — after the window
  had said nothing was armed. Every such path now cancels the ceremony and
  says so, and the wipe re-checks its target before firing.
- **Factory reset's throwaway PIN/PUK guesses are now random.** They were
  fixed constants that were themselves valid credentials, so a card whose real
  PUK happened to match had its PIN silently reset to a value published in the
  source while the wipe never ran. A guess that is accepted is now a hard error
  that names the resulting PIN and tells you to change it.
- **The CLI factory reset now verifies that the key you plugged back in is the
  key you confirmed.** Previously it reset whatever key was present after the
  replug prompt, so inserting a different key from a drawer of identical ones
  wiped that one instead. The GUI already had this guard.
- **A malicious or faulty security key can no longer make keyroost decompress
  unbounded data.** Reading an SSH certificate out of largeBlob storage took
  its size limit from a value the key itself supplied; there is now a host-side
  ceiling checked before any decompression runs.
- **Per-credential largeBlob keys are wiped from memory** after use, in all
  three places they were held.
- **keyroost no longer claims a Token2 key has the on-device OTP applet just
  because it is a Token2.** Capability was decided from the USB *vendor* id, so
  every Token2 key was offered the On-device OTP pane — including the
  configurations supplied without that applet, which then failed with a raw
  protocol error. The vendor's product id says which functions a unit actually
  has, so nine configurations (the FIDO-only, PGP-only and FIDO+PGP variants of
  PIN+ Mini, PIN+ Series and Bio3 Dual) no longer advertise OTP. A product id
  keyroost does not recognise still gets the feature offered, deliberately:
  hiding a function your key really has would be the worse mistake.

### Fixed
- **A key that has no on-device OTP now says so.** Where the key reports the
  function as absent, both the app and the CLI say it was supplied without it —
  and that Token2 keys cannot be upgraded after purchase, so it is not something
  to switch on — instead of surfacing a protocol error. `keyroostctl otp config`
  is never gated on this and now reports the capability explicitly, including
  "unknown" when the key answers with a short config block.
- **Security-key communication errors are explained rather than numbered.** A
  busy key reported only `CTAPHID_ERROR code 0x06`; each of the nine codes now
  carries a plain-language explanation with the specification's name alongside
  it. A busy channel is also retried briefly before being reported, which the
  specification asks clients to do and keyroost did not — that alone accounted
  for failures that cleared on their own moments later.
- **The retired PIV slots are a tab of their own.** They previously sat between
  the slot headings and the panes those headings introduce, listed as bare text
  under a heading whose caret rendered as a missing-glyph box. They now list all
  twenty in their own pane, marking which hold a key, and `Move key` has its own
  row and its own help rather than sharing the Delete heading — it is
  deliberately non-destructive and was filed under a destructive action.
- **A refusal to reset the wrong key names the right reason.** With an
  unrelated smart-card token also connected, refusing to wipe a key that was not
  the one confirmed reported that it "is not a different key" while a different
  key was plainly attached — a token with no security-key interface was being
  counted among the candidates.
- **The Molto2 troubleshooting guide names the real cause of "the token is
  never detected".** On distributions that start the smart-card service on
  demand, the service is usually not running between commands, so replugging
  notifies nothing and each command cold-starts it into the one attempt most
  likely to fail. Documented with the two checks that rule the token out first.
- **`cargo install keyroost` on Windows.** The Windows icon lived outside the
  published crate, so it was absent from the crates.io package and the build
  aborted. Nothing already released was affected — this would have first
  broken on the next release.
- **A card asking for a corrected length mid-transfer no longer restarts the
  whole command.** On strict readers this could re-run the original operation
  up to thousands of times — for `piv generate-key` that meant generating a
  fresh key pair each time — before failing with an unrelated-sounding error.
  Partial responses are now continued rather than discarded.
- **Reading a full-length card response no longer reports the applet as
  absent.** The probe's buffer had no room for the two status bytes, so a
  maximum-size response failed and the GUI hid a tab for a key that was there.
- **Factory reset can complete on keys that expose no serial number.** The
  new replug check refused them outright, which for a FIDO-only key meant the
  command could never succeed. Such a key is now accepted when it is
  unambiguously the only one connected, and refused the moment a second key
  is visible.
- **A blocked PUK no longer stops a factory reset short.** The blocking step
  used a fixed attempt cap instead of the card's real PUK retry count, so a
  card configured with more retries was left with its PIN blocked and nothing
  wiped.
- **Reset reports now tell the truth about the FIDO step.** The GUI summary
  omitted it entirely, so a FIDO reset that failed, was cancelled, or was
  never armed still read as a completed wipe; a later success could not
  correct an earlier failure; and an outcome could be painted onto a
  *different* key's report if the selection changed mid-ceremony.
- **Saving two SSH certificates at once no longer writes the wrong one.**
  Leaving one "Save certificate…" dialog open and starting another wrote the
  second certificate to the first one's filename.
- **A slow-to-reappear key is no longer accused of being the wrong key.** After
  the replug prompt, a key's serial is read over its card interface, which
  re-registers a moment after the FIDO one. keyroost waited under a second and
  then reported that a different key had been connected. It now waits up to
  three seconds — still well inside the reset window — and, when a key simply
  has not identified itself yet, says so instead of alleging a swap, naming the
  command that finishes the job.
- **A factory reset abandoned part-way now says what it did.** Selecting
  another key while the applets were being wiped discarded the whole report
  silently — including which applets had been erased and whether PIV had been
  left locked. It now records that in the log.
- **PIV reset failures are no longer all called permanent.** A card answering
  the reset with a transient or unspecific status was declared unrecoverable
  and the user was steered away from retrying. Only the statuses that genuinely
  mean the card has no reset instruction say that now.
- **Error messages no longer suggest commands that cannot run.** Several hints
  printed a command without its required `--yes`, or without its subcommand
  group, so following them verbatim failed — including the PIV recovery hint
  shown at exactly the moment it needs to work first try. The PIV hint also no
  longer claims a card is recoverable when the card has refused the reset with
  both credentials already blocked.
- **Smart-card vendor and serial now come from the card, not the reader**
  ([#83]). A Token2 smartcard in a third-party reader now shows the full
  device serial (read over any reader, including T=0 readers) and the vendor
  "Token2" — previously it showed only the 8-digit OpenPGP serial and the
  reader's name. OpenPGP cards from any vendor now get their correct vendor
  name via the standard manufacturer-ID registry.

## [0.7.6] - 2026-07-17

A bug-fix release for three field reports, plus the follow-through on the
v0.7.5 audit: deeper fuzz/property coverage and a self-healing release
pipeline.

### Fixed
- **CTAP 2.0-only keys can be reset again** ([#81]). The FIDO Settings tab —
  home of the "Reset this key" card — was gated on `authenticatorConfig`, a
  CTAP 2.1 feature, while reset itself is baseline CTAP 2.0. The tab now
  appears for any CTAP2 key; only the advanced security-policy controls
  inside it remain 2.1-gated.
- **Reset no longer hides behind the PIN it exists to recover from.** The
  Reset card now renders even when the key can't be unlocked — PIN forgotten
  or blocked, no PIN set, or no PIN support at all. `authenticatorReset`
  never needed a PIN; the GUI just wouldn't show it.
- **On-device OTP works again on firmware with a quirky HID dialect**
  ([#82]). Some keys answer the OTP-over-HID probe with a reply that omits
  the ISO status word, which v0.7.5's strict device binding surfaced as
  `unexpected status word 0x0105`. Automatic transport now falls back from
  USB-HID to the *same key's* smart-card interface — the pre-0.7.5
  resilience, without reopening the first-matching-key hole (KEY-003).
- The Passkeys tab is only offered on keys that actually support credential
  management, and the remembered tab selection snaps to a tab the selected
  key has (switching from a fingerprint key to one without a sensor no
  longer strands the pane on a ghost tab).
- Keys without `clientPin` support now say so, instead of showing
  "Reading key…" forever.
- **Flatpak clients can no longer be stranded on an old version** ([#80]).
  The AppStream release list is now generated from this changelog at bundle
  build time — the hand-maintained copy that silently fell three releases
  behind is gone, and CI fails any change where the changelog and workspace
  version disagree.

### Added
- Two new fuzz targets: the Windows HID interface-detail parser (the
  audit's KEY-020 surface) and the ISO 7816-4 `6C xx` retry classifier,
  which moved into `keyroost-proto` as `apdu::resend_with_le` to be
  fuzzable (new public API).
- Randomized property tests (dev-only, via proptest) over the GUI and CLI
  fail-closed device-binding guards and the terminal-output sanitizers.

### Changed
- The Linux bundle workflow can now be re-run out of band, publish.yml
  style: build-only probes from any branch, and tagged republishes into an
  existing release with a version guard and `flatpak_only` support.
- winget now waits for the Token2-signed Windows build and verifies its
  Authenticode signature before submitting — `winget install` may trail a
  release by a few days, in exchange for signed bytes and no more
  release-day races against Defender validation false positives. An
  expired winget token now fails the job loudly instead of skipping
  silently.

## [0.7.5] - 2026-07-14

A security-focused release: every open finding from an external security
audit (KEY-001..KEY-020) plus a full branch review is closed here. With thanks
to [Texas Cyber Command](https://www.txcc.texas.gov/) for a thorough,
actionable report.

### Security
- **Operations are bound to the exact device you selected.** Previously,
  several GUI flows (Molto2 sessions, FIDO PIN dialogs, OATH/OpenPGP
  confirmations, fingerprint and large-blob operations, the OTP pane) and the
  CLI `otp`/`molto` command groups could act on the *first matching* key or on
  a stale selection — with two keys plugged in, a write, delete, or factory
  reset confirmed for one key could land on the other. Every session, modal,
  and destructive confirmation now records the device it opened for, verifies
  it before acting, and is discarded when the selection changes. An armed FIDO
  reset re-identifies the replugged key by a stable serial and refuses to arm
  for a key that has none.
- **Two keys reporting the same serial no longer collapse into one identity.**
  Name resolution (`--device`, friendly names) fails closed with an ambiguity
  error instead of guessing, and the GUI warns that naming cannot tell such
  keys apart (they stay separately selectable).
- **Hostile or buggy devices can no longer panic or hang keyroost.** The
  published OATH, PIV, and OpenPGP byte layers return typed errors instead of
  panicking on device- or caller-supplied lengths; device-driven loops (OTP
  enumeration pages, fingerprint capture, wrong-length retries, the Windows
  HID path scan) are bounded by host-owned caps; and Linux hidraw reads are
  budgeted so a device that goes silent mid-response can't block forever.
- **Debug traces and terminal output leak less.** CTAP request payloads
  (friendly names, user entities) and large-blob traffic are redacted in
  debug traces; all terminal sanitization goes through one classifier
  covering the full set of spoofing/bidi/zero-width codepoints.
- **Secret file output is symlink-safe.** `keyroostctl`'s private-file writer
  creates an exclusively-owned 0600 file and renames it into place, refusing
  symlinks, non-regular files, and foreign-owned destinations.
- **The release supply chain is pinned.** The AppImage/Flatpak build inputs
  (cargo-sources generator, its Python deps, linuxdeploy, the Flatpak builder
  image) are pinned to immutable commits, content hashes, or digests and
  verified before execution; a CI policy check rejects any return to mutable
  refs; both bundles now ship sha256 sidecars and build-provenance
  attestations like the main archives.
- **6Cxx wrong-length retry regression fixed:** the retry no longer corrupts
  body-carrying Token2 OTP commands (it overwrote the last data byte of the
  encrypted seed with an Le byte).
- SECURITY.md now states precisely where `unsafe` exists (two Windows-only
  FFI shim crates); the workspace-wide forbid stands everywhere else.

### Fixed
- **On-demand HOTP codes on password-protected OATH keys.** The listing
  consumed the typed password, so "Read code" always sent an empty one and
  failed; the accepted password is now retained (zeroized) for follow-up
  reads and dropped on rejection or device switch.
- **Credential listing survives one malformed RP entry** from quirky
  authenticators instead of aborting the whole enumeration — and no longer
  queries a guessed RP hash for such entries.
- GUI settings and the key registry can no longer resolve to different
  config directories on Windows (the duplicated resolver that caused the
  earlier settings-persistence bug is gone).
- The rename field no longer keeps a 2 Hz repaint loop armed while open.

## [0.7.4] - 2026-07-06

### Added
- **Molto2 slot overview.** keyroost now reads each profile slot's stored title,
  occupancy, and TOTP configuration directly from the token, so the GUI slot
  list and the new `keyroostctl molto slots` command show what's actually on the
  device instead of tracking it blind. Adds title-only editing (rename a slot
  without re-entering its seed), per-slot **seed deletion** (`keyroostctl molto
  delete`, confirm-gated in the GUI), title read-back (`molto title -p <N>`), and
  a "Refresh slots" button that re-reads on demand. The wire format is documented
  in `docs/PROTOCOL.md`. **Security note:** slot titles and occupancy are
  readable by anyone holding the token — no customer key needed — so don't put
  secrets in titles.
- **FIDO2 large-blob legibility.** The Storage view classifies each large-blob
  entry (keyroost note / OpenSSH certificate / opaque relying-party data),
  decodes recognized ones (including parsed SSH-certificate validity), shows a
  capacity meter, and can export any entry to a file. `keyroostctl large-blob
  list`/`get` gain the same classification and a capacity line, plus a new
  `export` subcommand.

### Fixed
- **Change-PIN now confirms the new PIN.** The GUI change-PIN flow asked for the
  new PIN only once, unlike the set-PIN flow, so a typo could be committed and
  lock the key. It now requires a matching confirmation entry with the same
  validation as set-PIN, and zeroizes the typed PINs from memory when the dialog
  closes. Thanks to [@token2](https://github.com/token2) and @jurjendevries
  ([#79](https://github.com/framefilter/keyroost/issues/79)).
- **AppImage: a clear message when `libpcsclite` is missing.** The AppImage needs
  the host's PC/SC client library to start; without it the app aborted at the
  dynamic linker with a cryptic error. It now prints an actionable,
  per-distribution "install pcscd" message instead
  ([#78](https://github.com/framefilter/keyroost/issues/78)).
- **The CLI no longer panics on a closed output pipe.** Piping long output into
  `head` (or any early-closing reader) dumped a Rust backtrace; it now exits
  quietly, like a normal Unix filter.
- **Terminal-escape hardening.** Device-provided strings — serial numbers,
  certificate fields, Molto2 titles — are stripped of control characters before
  they reach the terminal, closing an escape-injection vector.
- The GUI's Molto2 slot list refreshes after writes and factory resets instead
  of showing stale data, and `keyroostctl molto slots --json` emits a
  serial-bearing, parseable JSON object.

### Changed
- The Learn site (`framefilter.github.io/keyroost`) gains a Molto2
  troubleshooting section and now deploys through a GitHub Actions workflow.
  `docs/PROTOCOL.md` documents the Molto2 per-profile read (`0x41`) and keyless
  seed delete (`0xE6`).
- **winget:** `Framefilter.Keyroost` is now live in the Microsoft catalog —
  `winget install Framefilter.Keyroost`.

## [0.7.3] - 2026-06-30

### Added
- **Windows: non-admin FIDO2 detection** — an unelevated process can't read a
  FIDO key's HID usage page on Windows, so FIDO-only keys used to disappear from
  the device list with no explanation. keyroost now detects the key via the
  access-denied signal and shows an "Administrator rights needed" card in the
  FIDO2 tab, with buttons to open Windows' built-in security-key settings or to
  relaunch elevated (new `keyroost-winwebauthn` helper crate). Thanks to
  [@token2](https://github.com/token2)
  ([#58](https://github.com/framefilter/keyroost/issues/58),
  [#62](https://github.com/framefilter/keyroost/pull/62)).
- **`KEYROOST_X11=1`** — opt-in environment variable that forces the GUI onto
  XWayland, a fallback for Wayland compositors where native input misbehaves.

### Fixed
- **GUI text input on Wayland / KDE Plasma** — on some compositors (notably KDE
  Plasma 6.7) the window lost keyboard focus shortly after startup and no field
  accepted typed input. The UI-toolkit update (below) resolves it; native
  Wayland input works again
  ([#48](https://github.com/framefilter/keyroost/issues/48)).
- **Light-theme zoom control** — the "Text size" slider, its handle and the ±
  steppers were nearly invisible on the light theme; they now use a contrasting
  control colour. The ± steppers also no longer slide out from under the cursor
  during repeated clicks — they preview and apply once you settle
  ([#59](https://github.com/framefilter/keyroost/issues/59),
  [#42](https://github.com/framefilter/keyroost/issues/42)).
- **winget (Windows):** the package manifest now declares the
  `Microsoft.VCRedist.2015+.x64` dependency, so winget pulls in the VC++
  runtime the Windows build needs alongside keyroost.

### Changed
- **UI toolkit updated** (egui/eframe 0.29 → 0.35) — this fixed the Wayland/KDE
  input bug above and is a sizeable refresh of the GUI layer. It should look and
  behave just as before, but **please
  [open an issue](https://github.com/framefilter/keyroost/issues) if you spot
  anything off** so it can be polished. Building from source now requires
  **Rust 1.85** or newer.

## [0.7.2] - 2026-06-26

### Added
- **Token2 single-profile programmable TOTP token** — a `keyroostctl prog`
  group (`info` / `seed` / `config`) and a GUI pane that program the seed and
  TOTP configuration onto Token2's single-account card/fob tokens (OTPC-P1-i /
  P2-i, miniOTP-2-i / 3-i, C301-i, C302-i) over a PC/SC reader, authenticating
  with the device's fixed key (no customer key, single slot). A new pure-Rust
  `keyroost-token2prog` crate carries the wire protocol — a close relative of
  the Molto2's (same SM4 cipher and ISO/IEC 9797-1 MAC) — documented
  independently in `docs/PROTOCOL-token2prog.md`. The write commands refuse to
  run unless the device serial matches a known model
  ([#49](https://github.com/framefilter/keyroost/pull/49)).
- **Contact-reader (ISO-7816 T=0) support** — FIDO2 and on-device OATH now work
  over a contact / chip reader as well as NFC, completing the PC/SC transport
  begun in 0.7.0 (the `61 XX` / `GET RESPONSE` and `6C XX` continuations are
  reassembled for T=0 readers)
  ([#43](https://github.com/framefilter/keyroost/issues/43)).
- **QR-from-screen scanning** — the `qr` import feature can now scan a QR code
  straight from the live screen, in addition to PNG/JPEG screenshots and Google
  Authenticator export batches, and is compiled into the pre-built release and
  AppImage binaries ([#50](https://github.com/framefilter/keyroost/pull/50)).
- **OTP secret reveal toggle** — secret-entry fields in the GUI gain a reveal
  (eye) toggle so you can verify an OTP secret before committing it
  ([#52](https://github.com/framefilter/keyroost/issues/52)).
- **Fuller passkey details** — resident-credential metadata now surfaces the
  user's UPN, display name, user id, and the full credential id
  ([#55](https://github.com/framefilter/keyroost/issues/55)).
- **AppImage AppStream metainfo + zsync** — the AppImage now ships AppStream
  metainfo and a `.zsync` sidecar for delta updates
  ([#53](https://github.com/framefilter/keyroost/pull/53)).

### Changed
- **Relaxed, anti-spoofing device naming + Windows config path** — friendly
  device names accept a more permissive, readable character set while being
  validated against spoofing (e.g. homoglyph / control-character) tricks, and
  the `keys.json` registry is saved under `%APPDATA%` on Windows
  ([#56](https://github.com/framefilter/keyroost/issues/56)).

### Fixed
- **Duplicate device entries when several keys are plugged in** — keys are now
  de-duplicated by USB topology, so the same physical key no longer appears more
  than once during enumeration
  ([#51](https://github.com/framefilter/keyroost/pull/51)).
- **AppImage uses the host's pcsc-lite** — the AppImage no longer bundles its
  own libpcsclite, instead linking the host's so the smart-card client always
  matches the host `pcscd` daemon
  ([#47](https://github.com/framefilter/keyroost/pull/47)).

## [0.7.1] - 2026-06-21

A bugfix release: it repairs the Flatpak repository install (broken in 0.7.0)
and two text-size controls in the GUI. No library or protocol changes — the
`keyroost-*` crates are unchanged save for the version bump.

### Fixed
- **Flatpak repo install failed GPG verification** — the published OSTree repo
  signed only its summary, not the commit objects, so installing from the remote
  failed with *"GPG verification enabled, but no signatures found"* even though
  `flatpak remote-info` (which checks only the summary) succeeded. The release
  workflow now signs the commits (`flatpak build-sign`) before refreshing the
  summary. The offline `.flatpak` bundle attached to each release was unaffected.
  Reported by [@errant253](https://github.com/errant253)
  ([#46](https://github.com/framefilter/keyroost/issues/46)).
- **GUI text-size slider jumped at the 99%↔100% boundary** — the percentage
  readout grew from 3 to 4 characters as the value crossed 100%, and in the top
  bar's right-to-left layout the wider label shifted the slider track under the
  cursor, making the value lurch (to ~110% going up, ~87% coming back down). The
  readout now reserves a fixed width, so the track stays put. Reported by
  [@StefanSa](https://github.com/StefanSa) with a detailed repro from
  [@errant253](https://github.com/errant253)
  ([#42](https://github.com/framefilter/keyroost/issues/42)).
- **Ctrl +/- zoom ignored the 80–200% bounds** — keyboard and scroll zoom could
  scale the interface past the slider's limits (roughly 20–500%) while the
  readout and the persisted value capped at 200%. Keyboard zoom is now clamped to
  the same range as the slider
  ([#42](https://github.com/framefilter/keyroost/issues/42)).

### Changed
- **README** — the winget entry is marked pending Microsoft's catalog review (the
  manifest is submitted but not yet merged into the public catalog), and the
  available-channels summary now reflects the Flatpak and AppImage bundles that
  shipped in 0.7.0. Prompted by [@errant253](https://github.com/errant253)
  ([#46](https://github.com/framefilter/keyroost/issues/46)).
- **README — supported-devices accuracy + a Roadmap section.** Corrected the
  device table (dropped dated framing, fixed an OpenPGP line that implied a
  standalone "register for GnuPG" command when the fingerprint/timestamp is
  written by generate/import, and added a row describing behavior on any
  standards-compliant FIDO2 key), and added a Roadmap section listing planned
  OnlyKey support ([#37](https://github.com/framefilter/keyroost/issues/37)) and
  inviting hardware-support requests via issues.

## [0.7.0] - 2026-06-20

### Added
- **FIDO2 over NFC readers** — a `CtapTransport` abstraction lets the CTAP
  command layer run over PC/SC as well as USB-HID, so FIDO2 (getInfo, passkey
  management) and on-device OTP now work through an NFC reader, not just direct
  USB. Contact / ISO-7816 chip readers are not yet supported (the contact path
  is deferred to follow-up; the PC/SC transport is shared, so it's an
  incremental fix). Contributed by Emin Huseynov / [@token2](https://github.com/token2)
  ([#44](https://github.com/framefilter/keyroost/pull/44), addressing
  [#43](https://github.com/framefilter/keyroost/issues/43)).
- **OpenPGP INTERNAL AUTHENTICATE** — `openpgp authenticate` produces a
  client/SSH authentication signature with the on-card Authentication key
  (PW1 in the "other" context). The Auth key slot is now selectable for
  provisioning too (`openpgp generate-key --slot auth`, `openpgp import-key
  --slot auth`), completing the third OpenPGP key.
- **PIV slot clearing** — `piv delete-cert` removes a slot's X.509 certificate
  object while leaving the private key in place (standard PIV; works on every
  card), and `piv delete-key` permanently erases a slot's private key (a Yubico
  extension requiring YubiKey firmware 5.7 or newer). Both need the management
  key and require an explicit `--yes`.
- **CTAP 2.1 authenticator config and large-blob storage** — a `fido large-blob`
  group (`list` / `get` / `add` / `edit` / `delete` / `clear`) reads and edits a
  key's `authenticatorLargeBlobs` array, keeping keyroost's own plaintext notes
  alongside relying-party entries (writes pull a `largeBlobWrite` token from the
  PIN and re-read the live array so RP entries are never clobbered; the store is
  world-readable, so it is for notes, not secrets). FIDO security-policy controls
  over `authenticatorConfig` — always-require-UV, raise minimum PIN length, force
  a PIN change, and enable enterprise attestation — plus a FIDO2 tab redesign in
  the GUI. Contributed by [@token2](https://github.com/token2)
  ([#38](https://github.com/framefilter/keyroost/pull/38)).
- **Linux desktop bundles** — a self-hosted Flatpak (signed OSTree remote with
  auto-update, plus an offline `.flatpak` bundle) and an AppImage of the GUI,
  both built by a new `linux-bundles.yml` workflow that triggers on `v*` tags and
  is gated behind the same `release-publish` approval as the other channels. The
  Flatpak OSTree is hosted in a dedicated `keyroost-flatpak` Pages repo (Flathub
  is intentionally not used). A Homebrew tap (`framefilter/homebrew-keyroost`)
  rounds out the fanout. (Flatpak ships the pcsc-lite client lib and talks to the
  host `pcscd`; end-to-end hardware verification of the sandboxed bundles is still
  pending.)

### Changed
- **Consolidated, card-based GUI across the FIDO2, PIV, and OpenPGP panes** — a
  significant redesign so every applet pane shares one visual vocabulary:
  per-slot / per-key sub-tab strips (PIV 9A/9C/9D/9E, OpenPGP sig/enc/auth),
  full-width cards with right-pinned actions, inline `?` help bubbles in place of
  verbose notes, and a global content-width cap (~920px, centered) that fixes the
  wide-window label↔action gap. Applet-wide administration (PIN/PUK, retries,
  management key, reset) is folded into each pane's status card instead of
  floating loose, and secret entry routes through a centered, scroll-independent
  credential modal that shows the operation result in place.
- **Vendor-neutral applet support, documented as such** — the OATH, OpenPGP, and
  PIV byte layers are open-standard implementations that work over CCID with any
  card exposing those applets (YubiKey, Nitrokey, SoloKeys, Feitian, Token2,
  OpenSK, …), not just YubiKeys; the README capability matrix and the github.io
  pages were reconciled to say so
  ([#41](https://github.com/framefilter/keyroost/issues/41)). The OATH / OpenPGP
  / PIV applets on the Token2 PIN+ are this same standards code; they remain
  marked experimental only because the project has not yet exercised them on
  physical PIN+ hardware.
- **Friendlier README intro** — a more approachable opening and a "What it is"
  framing so the project reads clearly to newcomers. Readability suggestion by
  [@errant253](https://github.com/errant253)
  ([#45](https://github.com/framefilter/keyroost/pull/45); the accompanying
  install script was declined).

### Fixed
- **Canonical CBOR key order in large-blob writes** — large-blob payloads now
  emit map keys in canonical order (parameter `0x05` before protocol `0x06`), so
  spec-strict authenticators (Solo 2, Nitrokey) accept the writes. YubiKey is
  lenient, which is why the earlier hardware round-trip passed.
- **Large-blob deletes no longer clobber relying-party entries** — the GUI delete
  path now re-reads the live large-blob array in the worker and removes the
  matching entry by content, instead of writing back a stale cached array. This
  protects RP entries written since the array was last loaded and avoids a
  position-shift wrong-delete (matching the add/edit/CLI paths).
- **Clearer destructive-action wording** — the "Clear all storage" action and the
  FIDO reset-dialog hint now state plainly that clearing erases every large-blob
  entry, including relying-party data, not just keyroost's notes.
- **OATH unlock submits on Enter** — pressing Enter in the OATH unlock field now
  submits, matching the FIDO2 unlock card and the rest of the redesign.

## [0.6.0] - 2026-06-17

### Added
- **Device-centric bare overview** — running `keyroostctl` with no subcommand
  now prints a device-centric overview of what is connected, and `list` is
  enriched with per-device detail (applets, serials, friendly names).
- **`--name` targeting on every group** — the friendly-name selector now works
  across all command groups (`molto`, `fido`, `oath`, `openpgp`, `piv`, `otp`),
  not just a subset, so one named key can be addressed consistently everywhere.
- **Per-group man pages** — `keyroostctl manpage <DIR>` now writes a directory
  set of man pages (one per command group) instead of a single page on stdout.
- **Global `--json` output mode** for the status/query commands — `list` /
  overview, `*/status`, `*/info`, `fido pin-retries` / `creds-list` /
  `creds-metadata`, `oath list` / `code`, and `otp list` / `get` / `serial` can
  now emit machine-readable JSON instead of human text.
- **OpenPGP PIN management** — `openpgp change-pin`, `openpgp change-admin-pin`,
  and `openpgp unblock-pin`, closing the OpenPGP PIN-management gap.
- **Token2 PIN+ fingerprint enrollment** (`fido fingerprint-list` / `enroll` /
  `rename` / `delete`), FIDO Metadata Service (MDS) metadata in the GUI, and
  on-device OTP improvements — contributed by
  [@token2](https://github.com/token2)
  ([#29](https://github.com/framefilter/keyroost/pull/29),
  [#30](https://github.com/framefilter/keyroost/pull/30)).
- **GUI PIV pane detail** — each slot now shows its certificate Subject DN and
  key algorithm, and a slot holding a key with no certificate is distinguished
  from an empty one; the pane auto-refreshes after a write
  ([#31](https://github.com/framefilter/keyroost/issues/31)).
- **In-tree X.509 Subject-DN reader** (`keyroost-piv`) — a small, panic-safe,
  dependency-free DER certificate reader backing the slot display above.
- **Confirm-PIN fields** on the GUI PIV Change-PIN and Change-PUK dialogs, so a
  mistyped new PIN can't lock the card
  ([#36](https://github.com/framefilter/keyroost/issues/36)).

### Changed
- **BREAKING: commands nested under `molto` and `fido` groups.** The flat
  Molto2 and FIDO subcommands have been moved under `molto …` and `fido …`.
  Key renames: `info` → `molto info`, `import`/`import-file` →
  `molto import`/`molto import-file`, `set-seed`/`set-title`/`configure` →
  `molto seed`/`molto title`/`molto config`, `set-customer-key` →
  `molto customer-key`, `factory-reset` → `molto reset`, and every `fido-*`
  command → `fido *` (e.g. `fido-info` → `fido info`, `fido-creds-list` →
  `fido creds-list`). The customer-key flags (`--key`, `--key-env`, …) now live
  under `molto customer-key`. See the migration table in the README for the full
  old→new map.

### Fixed
- **Firmware-accurate PIN guidance in the GUI** — removed the inaccurate "touch
  the key to confirm" hint from the FIDO set/change-PIN flow (CTAP PIN changes
  are not touch-gated) and corrected the PIN/PUK length text per applet
  ([#36](https://github.com/framefilter/keyroost/issues/36)).

## [0.5.1] - 2026-06-14

A follow-up to the Token2-vs-Molto2 device-identification fix.

### Fixed
- Molto2 reader matching keys on the product-name word only ("molto"), not the
  broader Token2 brand string, so a Token2 PIN+ / FIDO2 key is no longer
  mis-detected as a Molto2 (#21).

## [0.5.0] - 2026-06-14

On-device OTP for Token2 FIDO security keys joins the Molto2 programmer.

### Added
- **On-device TOTP/HOTP for Token2 FIDO keys (PIN+ / FIDO2+)** — a pure-Rust
  byte/codec layer (`keyroost-token2otp`) plus CLI (`otp` group) and GUI surface
  to enumerate, read, add, and delete OTP credentials stored on a Token2 FIDO
  security key over USB-HID, including the touch/button-HOTP slot and serial
  read. Contributed by @token2, built from the protocol reference they published
  (#20).

### Fixed
- Token2 FIDO keys no longer masquerade as a ghost Molto2 during device
  enumeration (#21).
- The crates.io "already published?" probe now sends a User-Agent, which some
  endpoints require.

### Docs
- Credit @token2 in a Contributors acknowledgement.

## [0.4.0] - 2026-06-12

Full PIV management, screenshot QR import, package-manager distribution, a
fuzzing suite, and a broad security-hardening pass.

### Added
- **Full PIV management** — beyond read-only status: client/card authentication
  (GENERAL AUTHENTICATE), key generation, certificate import/export,
  PIN/PUK/management-key changes, and applet reset, plus card-signed
  certificates (self-sign into a slot, or emit a CSR for a CA).
- **QR-code import** — pull 2FA secrets from PNG/JPEG screenshots, including
  Google Authenticator export batches.
- **Package-manager distribution** — automated release fanout to crates.io, AUR,
  Homebrew, and winget; `cargo binstall` targets the attested release archives.
- **Fuzzing** — `cargo-fuzz` targets for every hand-rolled parser, run weekly in
  CI.
- **`doctor`, `completions`, and `manpage` subcommands** — environment diagnosis
  and generated shell-completion / man-page artifacts.
- **Supply-chain CI** — a `cargo audit` (RUSTSEC) job on lockfile changes and
  weekly, SHA-256 release checksums, and build-provenance attestation on
  published archives.
- **SECURITY.md** — threat model, security invariants, and disclosure policy.

### Changed
- GUI bulk imports run on a dedicated thread instead of the frame loop, and a
  single shared scroller backs every capability pane.

### Fixed
- Broad post-review hardening: zeroize session secrets, CLI-read PINs, imported
  TOTP seeds, and extracted RSA components on drop; bound device-driven loops
  and lengths; strict base32 padding; cap attacker-controlled scrypt parameters
  in encrypted Aegis vaults; reject `otpauth` secrets over the device's 63-byte
  cap at parse time; atomic owner-only `keys.json` writes with field
  sanitization; redact secret-bearing APDU bodies from `--debug` traces.

### Notes
- The crates.io fanout skips publishing until OIDC / trusted-publishing is
  configured; the other targets and the GitHub Release run unconditionally.

## [0.3.0] - 2026-06-08

keyroost goes cross-platform: macOS and Windows join Linux, with a HID backend
that works on all three, a three-OS CI matrix, and a release pipeline that
attaches ready-to-run binaries for each.

### Added
- **macOS and Windows support** — a `hidapi`-based HID backend covers FIDO
  enumeration on macOS (IOKit) and Windows (hid.dll) alongside the existing
  Linux sysfs/hidraw path; PC/SC (OATH / OpenPGP / PIV / Molto2) was already
  cross-platform. `keyroost_hid::hid_supported()` lets front-ends tell "no FIDO
  devices plugged in" apart from "no HID backend on this platform".
- **Pre-built release binaries for all three OSes** — pushing a `vX.Y.Z` tag now
  cuts a public GitHub Release with a Linux x86_64 tarball, a macOS `universal2`
  tarball (`lipo`'d aarch64 + x86_64, one artifact for Apple Silicon and Intel),
  and a Windows zip, with auto-generated notes. A `workflow_dispatch` trigger
  builds the same archives off a branch for smoke-testing without tagging.
- **Three-OS CI matrix plus Fedora/Arch build verification** — Linux, macOS, and
  Windows build/test on every push, and `fedora:latest` / `archlinux:latest`
  container builds verify the documented per-distro package lists rather than
  assuming them.

### Changed
- The GUI empty state now states explicitly when FIDO keys aren't supported on
  the current platform (and notes that the smart-card features still work), so a
  missing-backend case doesn't read as a bug.
- User-facing "is pcscd running?" messages across transport / resolve / CLI are
  reworded to platform-neutral smart-card-service language.
- `CtapHidDevice::open` returns a clear `HidTransportError::Unsupported` on
  platforms without a HID backend instead of an opaque file-open failure.

### Docs
- README gains full Debian / Fedora-RHEL / Arch prerequisite blocks split into
  CLI vs GUI dependencies, corrects the stale "HID is Linux-only" note, and warns
  that the Ubuntu-built release binaries may not run on older-glibc distros
  (build from source there).

### Notes
- The macOS and Windows release jobs are exercised by `workflow_dispatch`; run
  the release workflow manually once before tagging if the build environment has
  changed.

## [0.2.0] - 2026-06-06

A device-centric GUI redesign, reliable hotplug, a FIDO reset that actually
fits the hardware's window, and the OpenPGP write surface rounded out.

### Added
- **Device-centric GUI** — a persistent sidebar listing each *physical* key once
  with merged capability badges, per-device capability tabs (Overview / FIDO2 /
  OATH / OpenPGP / PIV), and a distinct Molto2 view. Dark/light themes, accent
  colors, a colorblind-safe palette (Okabe–Ito), opaque help popovers, a global
  activity log, and a welcoming empty state. Bundled IBM Plex Sans / JetBrains
  Mono.
- **Reader hotplug auto-detect** — a PC/SC PnP-notification watcher re-enumerates
  on plug/unplug, with a staggered rescan burst so a slow-registering reader
  appears without a manual refresh.
- **FIDO reset that beats the ~10 s window** — arm the reset, then re-insert the
  key; it fires on reconnection (matched by HID serial, so any USB port works)
  and prompts for the touch.
- **OpenPGP PIN management** — change the user PIN (PW1) and admin PIN (PW3), and
  unblock a blocked user PIN with the admin PIN (`RESET RETRY COUNTER`), in a
  rebuilt themed write panel (admin PIN, card details, keys, PINs, reset).
- **Learn site "Naming" page** documenting friendly device names.

### Changed
- Interactive controls (buttons, segmented controls, device rows, icons) gained
  clear hover/press states and a pointing-hand cursor.
- Single-pass PC/SC enumeration; the Molto2 is listed by name and never
  connected during a scan (a probe connect intermittently wedged its CCID slot),
  so refreshing no longer disturbs a held, authenticated Molto2 session.

### Fixed
- CTAP `getKeyAgreement` now declares the negotiated PIN/UV protocol, fixing
  Set/Change PIN on authenticators that strictly enforce it (e.g. YubiKey).
- Empty resident-credential enumeration (`CTAP2_ERR_NO_CREDENTIALS`) is reported
  as "no passkeys", not an error.

### Notes
- Molto2 PC/SC detection on some hosts is bounded by a libccid USB-init timeout
  *below* the application; a direct USB port (avoiding hub chains) is the
  mitigation.
- Still Linux-only; Windows/macOS support is on the roadmap.

## [0.1.0] - 2026-06-02

The first release. keyroost grew from a Token2 Molto2 TOTP programmer into a
multi-vendor hardware-security-key manager, then took its neutral name. Highlights:

### Added
- **FIDO2 / CTAP2** — authenticator enumeration, `authenticatorGetInfo`, resident
  credential management (list / metadata / delete), PIN set/change/verify, reset.
  PIN protocols v1 and v2.
- **OATH (TOTP/HOTP)** over PC/SC — list, add, delete, compute codes, and the
  Yubico applet-password handshake (`SET_CODE` / `VALIDATE`, set/clear/unlock).
- **OpenPGP card (v3.4)** — status; RSA-2048 key generate and import (host keygen
  or PKCS#1/PKCS#8 PEM/DER file); sign (SHA-256 / SHA-1); decrypt (PSO:DECIPHER,
  extended-length + command-chaining); set cardholder name / URL; GnuPG key
  registration; applet reset.
- **PIV (SP 800-73-4)** — read-only status: applet/firmware version, serial, PIN
  retries, and per-slot (9A/9C/9D/9E) certificate presence.
- **Token2 Molto2 / Molto2v2** — slot programming from `otpauth://`; bulk import
  from Aegis (plaintext/encrypted), 2FAS, and `otpauth://` lists; time sync;
  customer-key rotation; factory reset.
- **Friendly device names** — opt-in `keys.json` registry and safe multi-key
  selection (USB + CCID serials, USB-topology matching).
- A CLI (`keyroostctl`) and an egui desktop GUI (`keyroost`).

### Notes
- Linux-only for now (HID enumeration uses sysfs; PC/SC is cross-platform).
- Crypto is pure-Rust and verified against standard test vectors; the only
  external dependencies are `pcsc`, `clap`, `eframe`/`egui`, `serde`, and
  (for RSA keygen/parsing) `rsa`/`rand`.

[#51]: https://github.com/framefilter/keyroost/issues/51
[#80]: https://github.com/framefilter/keyroost/issues/80
[#81]: https://github.com/framefilter/keyroost/issues/81
[#82]: https://github.com/framefilter/keyroost/issues/82
[#83]: https://github.com/framefilter/keyroost/issues/83
[#84]: https://github.com/framefilter/keyroost/issues/84
[#95]: https://github.com/framefilter/keyroost/issues/95
[#96]: https://github.com/framefilter/keyroost/pull/96
[#97]: https://github.com/framefilter/keyroost/pull/97
[#98]: https://github.com/framefilter/keyroost/issues/98
[#101]: https://github.com/framefilter/keyroost/pull/101
[#102]: https://github.com/framefilter/keyroost/pull/102
[#103]: https://github.com/framefilter/keyroost/issues/103
[#104]: https://github.com/framefilter/keyroost/pull/104
[#106]: https://github.com/framefilter/keyroost/issues/106
[#107]: https://github.com/framefilter/keyroost/issues/107
[#109]: https://github.com/framefilter/keyroost/issues/109
[#110]: https://github.com/framefilter/keyroost/pull/110
[#113]: https://github.com/framefilter/keyroost/issues/113
[#114]: https://github.com/framefilter/keyroost/pull/114
[#116]: https://github.com/framefilter/keyroost/pull/116
[#118]: https://github.com/framefilter/keyroost/pull/118
[#119]: https://github.com/framefilter/keyroost/pull/119
[#124]: https://github.com/framefilter/keyroost/issues/124
[#125]: https://github.com/framefilter/keyroost/issues/125
[#127]: https://github.com/framefilter/keyroost/issues/127
[#128]: https://github.com/framefilter/keyroost/issues/128
[#130]: https://github.com/framefilter/keyroost/issues/130
[#131]: https://github.com/framefilter/keyroost/issues/131
[#147]: https://github.com/framefilter/keyroost/issues/147
[#151]: https://github.com/framefilter/keyroost/issues/151
[#152]: https://github.com/framefilter/keyroost/issues/152
[#154]: https://github.com/framefilter/keyroost/issues/154
[#155]: https://github.com/framefilter/keyroost/issues/155
[#157]: https://github.com/framefilter/keyroost/issues/157
[#160]: https://github.com/framefilter/keyroost/issues/160
[#161]: https://github.com/framefilter/keyroost/issues/161
[#163]: https://github.com/framefilter/keyroost/issues/163
[#164]: https://github.com/framefilter/keyroost/issues/164
[#165]: https://github.com/framefilter/keyroost/issues/165
[#166]: https://github.com/framefilter/keyroost/issues/166
[#167]: https://github.com/framefilter/keyroost/issues/167
[#170]: https://github.com/framefilter/keyroost/issues/170
[#171]: https://github.com/framefilter/keyroost/issues/171
[#174]: https://github.com/framefilter/keyroost/issues/174
[#176]: https://github.com/framefilter/keyroost/issues/176
[#177]: https://github.com/framefilter/keyroost/issues/177
[#184]: https://github.com/framefilter/keyroost/issues/184
[#185]: https://github.com/framefilter/keyroost/issues/185
[#188]: https://github.com/framefilter/keyroost/issues/188
[#189]: https://github.com/framefilter/keyroost/issues/189
[#190]: https://github.com/framefilter/keyroost/issues/190
[#195]: https://github.com/framefilter/keyroost/issues/195
[#199]: https://github.com/framefilter/keyroost/issues/199
[#200]: https://github.com/framefilter/keyroost/issues/200
[#201]: https://github.com/framefilter/keyroost/issues/201
[#202]: https://github.com/framefilter/keyroost/issues/202
[#203]: https://github.com/framefilter/keyroost/issues/203
[#204]: https://github.com/framefilter/keyroost/issues/204
[#205]: https://github.com/framefilter/keyroost/issues/205
[#206]: https://github.com/framefilter/keyroost/issues/206
[#208]: https://github.com/framefilter/keyroost/issues/208
[#211]: https://github.com/framefilter/keyroost/issues/211
[#212]: https://github.com/framefilter/keyroost/issues/212
[#215]: https://github.com/framefilter/keyroost/issues/215
[#216]: https://github.com/framefilter/keyroost/issues/216
[#217]: https://github.com/framefilter/keyroost/issues/217
[#218]: https://github.com/framefilter/keyroost/issues/218
[#220]: https://github.com/framefilter/keyroost/issues/220
[#221]: https://github.com/framefilter/keyroost/issues/221
[#222]: https://github.com/framefilter/keyroost/issues/222
[#223]: https://github.com/framefilter/keyroost/issues/223
[#224]: https://github.com/framefilter/keyroost/issues/224
[#225]: https://github.com/framefilter/keyroost/issues/225
[#226]: https://github.com/framefilter/keyroost/issues/226
[#227]: https://github.com/framefilter/keyroost/issues/227
[#228]: https://github.com/framefilter/keyroost/issues/228
[#230]: https://github.com/framefilter/keyroost/issues/230
[#231]: https://github.com/framefilter/keyroost/issues/231
[#232]: https://github.com/framefilter/keyroost/issues/232
[#233]: https://github.com/framefilter/keyroost/issues/233
[#235]: https://github.com/framefilter/keyroost/issues/235
[#236]: https://github.com/framefilter/keyroost/issues/236
[#237]: https://github.com/framefilter/keyroost/issues/237
[#243]: https://github.com/framefilter/keyroost/issues/243
[#244]: https://github.com/framefilter/keyroost/issues/244
[#245]: https://github.com/framefilter/keyroost/issues/245
[#246]: https://github.com/framefilter/keyroost/issues/246
[#249]: https://github.com/framefilter/keyroost/issues/249
[#251]: https://github.com/framefilter/keyroost/issues/251
[#252]: https://github.com/framefilter/keyroost/issues/252
[#253]: https://github.com/framefilter/keyroost/issues/253
[#254]: https://github.com/framefilter/keyroost/issues/254
[#256]: https://github.com/framefilter/keyroost/issues/256
[Unreleased]: https://github.com/framefilter/keyroost/compare/v0.16.0...HEAD
[0.16.0]: https://github.com/framefilter/keyroost/compare/v0.15.0...v0.16.0
[0.15.0]: https://github.com/framefilter/keyroost/compare/v0.14.0...v0.15.0
[0.14.0]: https://github.com/framefilter/keyroost/compare/v0.13.0...v0.14.0
[0.13.0]: https://github.com/framefilter/keyroost/compare/v0.12.0...v0.13.0
[0.12.0]: https://github.com/framefilter/keyroost/compare/v0.11.0...v0.12.0
[0.11.0]: https://github.com/framefilter/keyroost/compare/v0.10.0...v0.11.0
[0.10.0]: https://github.com/framefilter/keyroost/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/framefilter/keyroost/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/framefilter/keyroost/compare/v0.7.8...v0.8.0
[0.7.8]: https://github.com/framefilter/keyroost/compare/v0.7.7...v0.7.8
[0.7.7]: https://github.com/framefilter/keyroost/compare/v0.7.6...v0.7.7
[0.7.6]: https://github.com/framefilter/keyroost/compare/v0.7.5...v0.7.6
[0.7.5]: https://github.com/framefilter/keyroost/compare/v0.7.4...v0.7.5
[0.7.4]: https://github.com/framefilter/keyroost/compare/v0.7.3...v0.7.4
[0.7.3]: https://github.com/framefilter/keyroost/compare/v0.7.2...v0.7.3
[0.7.2]: https://github.com/framefilter/keyroost/compare/v0.7.1...v0.7.2
[0.7.1]: https://github.com/framefilter/keyroost/compare/v0.7.0...v0.7.1
[0.7.0]: https://github.com/framefilter/keyroost/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/framefilter/keyroost/compare/v0.5.1...v0.6.0
[0.5.1]: https://github.com/framefilter/keyroost/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/framefilter/keyroost/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/framefilter/keyroost/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/framefilter/keyroost/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/framefilter/keyroost/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/framefilter/keyroost/releases/tag/v0.1.0
