- **The Molto2 bulk import dialog closes and says why "Program all" is
  gray.** Close in the bulk import dialog, and Cancel in the "Import to
  slot" dialog, did nothing; both now close the dialog, and closing
  either dialog by any route wipes the typed vault password or pasted URI
  and drops the parsed entries (which carry seeds).
  When "Program all" can't run, one line under the buttons now says why:
  the file is still loading, no Molto2 is selected, the Molto2 isn't
  unlocked yet (with an Authenticate button right there, and a failed
  attempt is reported in that line too), or the entries
  don't all fit before slot #99 (with how many do). ([#170])
