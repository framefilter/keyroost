- **keyroostctl's piped output reads cleanly in PowerShell.** PowerShell
  decodes a program's piped or redirected output in the console's legacy
  code page, so keyroost's arrows, dashes and dots arrived as `ΓåÆ`, `ΓÇö`
  and `┬╖`. When its output goes to a pipe or a file on Windows,
  keyroostctl now writes those few characters in ASCII (`->`, `-`, `|`),
  in names too; the console, JSON and files it writes are unchanged.
  ([#249])
