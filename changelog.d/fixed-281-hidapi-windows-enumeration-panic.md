- **keyroost no longer stops with a panic while listing HID devices on
  some Windows PCs.** There hidapi 2.6.7 panicked ("Slice is not null
  terminated") as it enumerated devices, so `keyroostctl doctor` ended
  before it reported anything. Until a hidapi release carries the fix
  proposed upstream (ruabmbua/hidapi-rs#189), builds from this repository
  use hidapi at that fix's commit. A `cargo install` from crates.io still
  resolves hidapi as published. ([#281])
