- **A request that failed below the card shows its error in the trace.**
  When PC/SC itself refused a command (Windows' "access is denied", a
  removed card), `--debug` and the Activity log showed the request and no
  answer; the answer line now reads "PC/SC error: …". ([#250])
