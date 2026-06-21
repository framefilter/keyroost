# v0.7.5 TODO

Deferred items that are too large or too risky to fold into a same-day patch.
Captured here so they don't get lost. Unchecked = not started.

## PC/SC: load libpcsclite at runtime, degrade gracefully (the real #47 fix)

- [ ] Stop hard-linking libpcsclite; **`dlopen` it at runtime** in
      `keyroost-transport` (and wherever the `pcsc` crate is used), so:
  - the **host's** libpcsclite is always used — the only client guaranteed to
    match the host's `pcscd` daemon (fixes the version-mismatch root cause of
    [#47](https://github.com/framefilter/keyroost/issues/47) for **every**
    distribution channel, not just the AppImage); and
  - when libpcsclite is **absent**, keyroost still launches and FIDO/USB-HID
    keeps working — the PC/SC panes show a clear "PC/SC unavailable" state
    instead of the binary failing to start.
- [ ] This **removes the AppImage limitation** noted in
      `packaging/appimage/build-appimage.sh` (the 0.7.x AppImage drops the
      bundled libpcsclite and so needs the host's to even launch).
- [ ] The `pcsc` crate links at build time; check whether it exposes a
      dlopen/dynamic-load path or whether we wrap libpcsclite via a thin FFI
      loader ourselves. Design before implementing; verify on a host WITH and a
      host WITHOUT libpcsclite.

## egui / eframe version bump

- [ ] Bump **egui / eframe / egui-winit 0.29.1 → 0.34.3** (current latest).
      Five minor versions of breaking API changes across the ~11k-line GUI —
      treat as its own project with a full pass + regression check (zoom/slider,
      modals, layout, light/dark themes).
- [ ] **winit stays 0.30.13** either way (0.31 is beta only; egui 0.34 still
      rides the 0.30.x line), so this is **not** guaranteed to fix the Wayland
      text-input regression in
      [#48](https://github.com/framefilter/keyroost/issues/48) — but check
      whether egui-winit's glue changes incidentally resolve it on Fedora-44 KWin
      while we're here.

## GUI — Text-size control polish ([#42](https://github.com/framefilter/keyroost/issues/42), @token2)

- [ ] Add discrete **"−" / "+" buttons** on the ends of the zoom slider; mouse
      dragging is unpredictable near the boundaries.
- [ ] **Light theme:** the slider track/handle is almost invisible — restyle it
      so it reads on the light palette (it's currently tuned for dark only).
