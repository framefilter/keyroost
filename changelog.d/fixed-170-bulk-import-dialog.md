- **The Molto2 import dialog closes and says why adding is gray.** Close
  in the import dialog, and Cancel in the "Import to slot" dialog, did
  nothing; both now close the dialog, and closing either dialog by any
  route wipes the typed file password or pasted URI and drops the parsed
  entries (which carry seeds).
  When adding can't start, one line under the buttons now says why: the
  file is still loading, or the Molto2 isn't open or unlocked yet (with
  an Authenticate button right there, and a failed attempt is reported in
  that line too). ([#170])
