- **`prog` uses the token you choose.** It used to ignore `--device` and
  write to whichever reader was alone, programmable token or not. It now
  only considers programmable tokens and honours `--device` and
  `--reader`. ([#165])
