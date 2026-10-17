- **The Windows app draws with DirectX 12.** It now opens on computers
  without OpenGL 2.0, such as virtual machines without 3D acceleration and
  some remote-desktop sessions, where it couldn't start before. If DirectX
  12 doesn't work, it falls back to OpenGL. Linux and macOS are unchanged.
  ([#185])
