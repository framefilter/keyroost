# musl static build — design + runbook (DRAFT)

> **STATUS: DRAFT for maintainer review.** Not wired into CI. The PC/SC path
> here is an **unverified spike** — read the caveats. See `../LINUX-BUNDLES.md`
> for the cross-target picture.

## Recommendation in one line

**Build only the CLI (`keyroostctl`) as a `x86_64-unknown-linux-musl` static
binary. Do NOT attempt a musl static GUI.** The GUI's portability story is the
AppImage (`../appimage/`); musl is the fully-static, dependency-free CLI story.

## Why CLI-only

`eframe`/`egui` dynamically load the host graphics stack (`libxkbcommon`,
`libwayland`, `libxcb`, `libGL`, …). A "static musl GUI" would still `dlopen`
those at runtime, defeating the point and adding a musl-vs-glibc graphics
mismatch. The CLI has a small, mostly-pure-Rust dependency surface; its only
non-Rust link is `libpcsclite`.

## The one hard problem: libpcsclite under musl

`keyroostctl` links `libpcsclite` via `pcsc` → `pcsc-sys`, a direct FFI binding
(the published `pcsc` crate has **no dlopen feature** — verified against the
pcsc-rust README). pcsc-lite is glibc-oriented. On a fully-static musl target you
cannot link a glibc `libpcsclite`. Options, in order of preference:

### Option 1 (recommended) — static-link a musl-built libpcsclite

Cross-compile pcsc-lite itself against musl to get `libpcsclite.a`, then link it
statically. The binary becomes truly static **and** speaks PC/SC. The client lib
still talks to the **host pcscd** over a Unix socket at runtime — static linking
only removes the build/link dependency, never the daemon.

```bash
rustup target add x86_64-unknown-linux-musl

# Build pcsc-lite against musl first (separately), installing into a prefix.
# A musl cross toolchain is easiest inside a container that already has one,
# e.g.  ghcr.io/messense/rust-musl-cross:x86_64-musl  (or the official musl images).
# Inside that environment, configure pcsc-lite client-only and `make install`
# into /opt/musl-pcsclite. TODO(maintainer): pin pcsc-lite version + confirm the
# client-only configure flags (see the Flatpak manifest for the same flags).

# Point pcsc-sys at the musl-built static lib:
export PCSC_LIB_DIR=/opt/musl-pcsclite/lib        # contains libpcsclite.a
export PCSC_LIB_NAME=pcsclite
export RUSTFLAGS="-C target-feature=+crt-static"

cargo build --release --target x86_64-unknown-linux-musl -p keyroostctl

file target/x86_64-unknown-linux-musl/release/keyroostctl   # expect: statically linked
```

> **UNVERIFIED (flag for maintainer):** no off-the-shelf "libpcsclite against
> musl" recipe was found during research. This needs a spike: build pcsc-lite
> with a musl toolchain, confirm `pcsc-sys` finds the static lib, link, and
> smoke-test against a real host pcscd. Also confirm the exact `pcsc-sys` env
> var names (`PCSC_LIB_DIR`/`PCSC_LIB_NAME`) against the locked `pcsc-sys`
> version — they are build-script specific.

### Option 2 (fallback) — FIDO-only musl CLI (no PC/SC)

Compile `keyroostctl` with the PC/SC path removed. The pure-Rust
`keyroost-hid`/`keyroost-ctap` FIDO stack has no C deps and musl-links cleanly,
yielding a static FIDO-only binary — but it **loses Molto2/OATH/OpenPGP/PIV**
(all PC/SC).

> **Out of scope for these drafts:** there is no cargo feature today to compile
> out PC/SC, and adding one touches `Cargo.toml`. The task forbids dependency/
> manifest changes, so option 2 is documented but not draftable here. If chosen,
> it becomes a code change (feature-gate the `pcsc`/transport path), not a
> packaging-only change.

### Option 3 (not recommended) — musl with `-crt-static` off

`x86_64-unknown-linux-musl` with `-C target-feature=-crt-static` ("dynamic
musl") has historically ended up linking glibc anyway (known rust-lang issue),
so it is not a clean portability win. Skip it.

## Reproducible build path

Use a musl-cross container so the toolchain + a musl-built libpcsclite live in
one place:

```bash
docker run --rm -v "$PWD":/io -w /io \
    ghcr.io/messense/rust-musl-cross:x86_64-musl \
    bash -c '<build pcsc-lite against musl> && \
             PCSC_LIB_DIR=/opt/musl-pcsclite/lib PCSC_LIB_NAME=pcsclite \
             RUSTFLAGS="-C target-feature=+crt-static" \
             cargo build --release --target x86_64-unknown-linux-musl -p keyroostctl'
```

TODO(maintainer): pin the exact container image/tag for reproducibility.

## Runtime requirements (user side)

- A **host pcscd** must be running for the smart-card applets (static linking
  removes only the build dep, not the daemon).
- **FIDO HID** needs the host udev rules (`udev/70-keyroost-fido.rules`) for
  non-root `/dev/hidraw` access — same as every other target.
- No glibc needed (that's the whole point); runs across glibc *and* musl distros.

## Publish

The musl static `keyroostctl` is a natural extra **GitHub Release asset**
alongside the existing tarballs (a single portable CLI file). This draft does
**not** modify `release.yml`; adding the artifact would be a future, separate CI
step.

## Claims to double-check

- libpcsclite-against-musl static link (whole PC/SC path) — **unverified**.
- `pcsc-sys` env var names — conventional, version-specific, verify.
- pcsc-lite client-only configure flags — drift across versions, pin + verify.
