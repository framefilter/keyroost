- **The AppImage runs on older Linux systems and minimal setups.** It is now
  built on Ubuntu 22.04, so it needs glibc 2.35 rather than 2.39, and it
  bundles the keyboard libraries (`libxkbcommon`, `libxkbcommon-x11`) the
  windowing layer loads at runtime; without them it crashed at startup on
  systems that lack `libxkbcommon-x11`. The Linux release tarball is built
  on Ubuntu 22.04 as well. ([#160])
