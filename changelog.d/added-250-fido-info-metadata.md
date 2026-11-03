- **`fido info` names the key's model and its FIDO certification**, as the
  app's metadata card does: "Model", "Certification" (with the date it took
  effect) and "Protocol family" rows, and a `metadata` object in `--json`.
  The model table and the bundled FIDO metadata moved into a library the
  CLI and the app share, so both read the same data, including a
  `mds_data.json` you place to refresh it. ([#250])
