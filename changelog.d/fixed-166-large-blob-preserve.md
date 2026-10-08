- **Large-blob writes keep other tools' entries byte for byte.** Adding,
  editing or deleting an entry dropped fields keyroost didn't know from
  every other entry it wrote back. Entries keyroost doesn't change are now
  written back exactly as read, in order. ([#166])
