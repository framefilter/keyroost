- **A key selected while another was busy no longer stays on "Reading
  key…".** Its first read was refused while the other key's step ran, and
  only the FIDO2 tab tried again, so the Overview kept "Reading key…"
  until the next scan. The read now starts as soon as nothing else runs,
  on any tab. ([#254])
