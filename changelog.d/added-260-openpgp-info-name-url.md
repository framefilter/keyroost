- **`openpgp info` shows the cardholder name and public-key URL.** The
  CLI prints the `005B` name and `5F50` URL (`cardholder_name` and `url`
  in `--json`), and the app's Card details entries pre-fill from the
  card, keeping staged edits and dropping them on a card swap. ([#260])
