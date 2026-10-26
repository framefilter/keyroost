- **`doctor` and the app say when a key's smart-card part has no reader
  (Linux).** When a key has a smart-card interface but the smart-card service
  lists no reader for it, usually because the system's smart-card driver
  doesn't know the model yet, `doctor` says so and the app adds a line to the
  key's Overview page. ([#215])
