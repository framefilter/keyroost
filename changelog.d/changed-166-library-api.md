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
