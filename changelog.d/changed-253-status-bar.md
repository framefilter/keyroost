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
