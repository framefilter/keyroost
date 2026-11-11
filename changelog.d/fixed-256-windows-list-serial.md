- **`keyroostctl list` on Windows shows a key's serial on its FIDO line.**
  Windows reports an empty USB serial for a key that has none, and `list`
  printed a bare `serial=` instead of the serial read over the key's
  smart-card side. ([#256])
