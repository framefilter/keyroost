- **The screen output is split: result on stdout, the rest on stderr.**
  Prompts, progress, "Authenticated.", the Molto2 serial and clock lines
  (except in `molto info`, where they are the result) and "Wrote …" lines
  now go to stderr. So `keyroostctl molto slots > slots.txt` saves just the
  table, and you still see the rest. ([#165])
