# Linux bundle packaging — setup runbook (Flatpak self-host / AppImage) + musl notes

> **STATUS: WIRED for Flatpak + AppImage; musl is notes-only.** The Flatpak and
> AppImage targets are now wired into CI via
> [`.github/workflows/linux-bundles.yml`](../.github/workflows/linux-bundles.yml),
> which triggers on `v*` tags (the same trigger as `release.yml`). It does **not**
> modify `release.yml`/`publish.yml`. **musl is out of scope / not decided** —
> [Target 3](#target-3--musl-static-build) below is documentation only and is
> **not** wired into any workflow.
>
> Before a tagged release produces working bundles, do the
> [one-time maintainer setup](#one-time-maintainer-setup) (icon, pcsc-lite
> sha256, optional GPG key, Pages). Remaining open decisions are in
> [Decisions](#decisions) at the bottom — the resolved ones are marked **DECIDED**.

## One-time maintainer setup

Do these once; after that every `git push origin vX.Y.Z` builds + attaches the
bundles automatically.

1. **Icon (REQUIRED).** keyroost has no icon yet. Drop two files into
   `packaging/icons/` (filenames must match the app-id):
   - `io.github.framefilter.keyroost.svg`
   - `io.github.framefilter.keyroost-256.png`

   See [`packaging/icons/README.md`](icons/README.md). Until they exist, **both
   the Flatpak and AppImage builds fail at the icon-install step** — by design.

2. **pcsc-lite sha256 (REQUIRED).** Pin the pcsc-lite client-lib tarball in
   `packaging/flatpak/io.github.framefilter.keyroost.yml`. The `sha256:` is a
   `REPLACE_WITH_REAL_SHA256` placeholder (the upstream host could not be reached
   from the build environment to compute it). On a machine that can reach
   `pcsclite.apdu.fr`:

   ```bash
   ver=2.3.0   # pick the release you want; update the url version too
   curl -fsSLO "https://pcsclite.apdu.fr/files/pcsc-lite-${ver}.tar.bz2"
   sha256sum "pcsc-lite-${ver}.tar.bz2"
   ```

   `flatpak-builder` refuses to build until the sha256 matches, so this can never
   ship wrong. Also confirm the client-only `./configure` flags on the chosen
   version (flag names drift across pcsc-lite 1.9/2.x).

3. **Auto-update repo `framefilter/keyroost-flatpak` (REQUIRED for the
   auto-update remote).** The OSTree repo is hosted in a **dedicated** repo, NOT
   this one: this repo's `main` requires verified-signed commits a CI bot can't
   produce, so a separate repo sidesteps that and leaves the Learn site (served
   from this repo's `docs/`) completely untouched. One-time:
   - **Create** a public repo `framefilter/keyroost-flatpak` with **one initial
     commit** (an empty `README.md` is enough — `git clone` needs a branch to
     exist).
   - **Enable its Pages:** in that repo, Settings → Pages → Source **"Deploy from
     a branch"**, branch = its default, folder = **`/ (root)`**. It serves at
     `https://framefilter.github.io/keyroost-flatpak/`.
   - **Grant CI write access:** create a **fine-grained PAT** scoped to *only*
     `framefilter/keyroost-flatpak` with **Contents: Read and write**, and add it
     to **this** repo as the secret **`FLATPAK_REPO_TOKEN`**.
   - **Place the static descriptors** in the **root** of `keyroost-flatpak`: copy
     `packaging/flatpak/keyroost.flatpakrepo` there (as `keyroost.flatpakrepo`) and
     the icon SVG (as `keyroost-icon.svg`), so the one-click remote URL and its
     icon resolve. The release workflow overlays the OSTree tree alongside these on
     each tag and does **not** delete them.

   When `FLATPAK_REPO_TOKEN` is absent the OSTree-publish step **skips cleanly**:
   the `.flatpak` bundle is still attached to the release, only the auto-update
   remote won't refresh.

4. **Flatpak repo GPG key (OPTIONAL, recommended).** To sign the OSTree repo so
   `flatpak` verifies it, add two repository secrets:
   - `FLATPAK_GPG_KEY` — the ASCII-armored **private** signing key.
   - `FLATPAK_GPG_KEY_ID` — that key's id/fingerprint.

   Generate a dedicated repo-signing key (separate from any commit-signing key):

   ```bash
   # Use a non-personal UID so the published public key doesn't expose an email:
   gpg --quick-generate-key "keyroost Flatpak Repo Signing Key" ed25519 sign never
   gpg --armor --export-secret-keys <KEYID>   # -> paste into FLATPAK_GPG_KEY
   ```

   When these secrets are **absent the workflow skips signing cleanly** and
   publishes the repo **unsigned** (mirrors the `publish.yml` unset-secret
   pattern — no hard fail). After signing, paste the base64 public key into the
   `GPGKey=` line of `packaging/flatpak/keyroost.flatpakrepo`:
   `gpg --export <KEYID> | base64 --wrap=0`. The workflow also writes the public
   key to the root of `keyroost-flatpak` (`keyroost.gpg`) for reference.

5. **App-id — DECIDED.** `io.github.framefilter.keyroost`. No action needed.

## User install instructions

### Flatpak — auto-updating remote (recommended)

```bash
# one-time: add the remote from the one-click descriptor
flatpak remote-add --if-not-exists keyroost \
    https://framefilter.github.io/keyroost-flatpak/keyroost.flatpakrepo
flatpak install keyroost io.github.framefilter.keyroost
# updates ride along with `flatpak update`
```

### Flatpak — offline single-file bundle (no auto-update)

Download `keyroost.flatpak` from the GitHub Release, then:

```bash
flatpak install ./keyroost.flatpak
flatpak run io.github.framefilter.keyroost
```

### AppImage

Download `keyroost-x86_64.AppImage` from the GitHub Release, then:

```bash
chmod +x keyroost-x86_64.AppImage
./keyroost-x86_64.AppImage
# FUSE: on FUSE3-only distros install libfuse2, OR run without FUSE:
./keyroost-x86_64.AppImage --appimage-extract-and-run
```

For **non-root FIDO HID** access the user still installs the host udev rules
(`udev/70-keyroost-fido.rules`) — no bundle can do this for them. Smart-card
applets need a running **host `pcscd`** (every target talks to the host daemon).

## Known caveats / TODOs

- **cargo-sources.json** is generated on the runner each build from `Cargo.lock`
  (never committed, never stale). Verified June 2026: the generator yields 414
  crate archives + checksums, all from `static.crates.io`.
- **pcsc-lite sha256** is a placeholder — see setup step 2.
- **OSTree history growth:** the `keyroost-flatpak` repo accumulates OSTree
  objects over releases. Prune (`flatpak build-update-repo --prune`) periodically
  if it nears GitHub Pages' soft ~1 GB guidance.
- **Contact-vs-NFC** is unrelated to packaging (a PC/SC reader-mode concern, not
  a bundle concern) — do not conflate it with these targets.
- Everything is still **unverified on real hardware** end-to-end (Molto2 + a FIDO
  key in the Flatpak sandbox / AppImage). The `--filesystem=/run/udev:ro` and
  `--device=all` breadth need a hardware test (see Target 1).

---

> **Historical design notes follow.** The sections below are the original design
> rationale for each target; they remain accurate but the actionable runbook is
> above.

> **Naming note / decision:** the existing `packaging/README.md` is the
> *release-fanout one-time-setup* doc (crates.io / AUR / Homebrew / winget).
> This design doc was deliberately named `LINUX-BUNDLES.md` so it does **not**
> overwrite that file. If you'd rather this be the canonical `packaging/README.md`,
> that's a maintainer call (see decisions list). All paths below are relative to
> the repo root.

These three targets share one hard problem and one easy one:

- **Hard:** PC/SC. keyroost links `libpcsclite` and talks to a **host**
  `pcscd`. None of Flatpak's sandbox, an AppImage's bundled libs, or a musl
  static binary can run `pcscd` itself — they all must reach the *host* daemon.
  Each target solves this differently and each has a caveat called out below.
- **Easy:** FIDO HID. keyroost reads `/dev/hidraw*` via sysfs with no external
  C dependency (the `keyroost-hid` crate is pure Rust). The only requirement is
  that the process can *open* the hidraw node — a permissions/device-access
  question, not a linking one. The repo already ships udev rules
  (`udev/70-keyroost-fido.rules`) for the host case.

The project's GitHub is `framefilter/keyroost` and the Learn site is
`framefilter.github.io/keyroost`, which is why the drafts use the reverse-DNS
app-id **`io.github.framefilter.keyroost`** (a from-GitHub-Pages convention that
AppStream/Flatpak both bless). Confirm or change this — it's load-bearing for
Flatpak and AppStream and is the first decision below.

---

## Target 1 — Flatpak (self-hosted repo, NOT Flathub)

### Why self-host, not Flathub

Flathub has a stated stance against AI-generated submissions, and keyroost is
openly AI-authored. So a Flathub submission is **off the table by design** — but
Flatpak the *technology* is not. Flatpak's value (distro-agnostic install,
sandbox, delta auto-updates, GPG-verified) is fully available from a
**self-hosted OSTree repo** you publish yourself; Flathub is just *one* remote.
Yubico Authenticator and KeePassXC prove the PC/SC-over-Flatpak pattern works.

### How a self-hosted Flatpak repo works

A Flatpak "repo" is an [OSTree](https://ostreedev.github.io/ostree/)
repository — a content-addressed object store — served as **plain static files
over HTTPS**. There is no app server. The publish pipeline is:

1. `flatpak-builder --repo=<repodir> <builddir> <manifest>` builds the app into
   a local OSTree repo directory.
2. `flatpak build-update-repo [--gpg-sign=KEYID] <repodir>` regenerates the
   summary/metadata (and signs it).
3. You `rsync`/upload `<repodir>` to any static host. Two realistic hosts:
   - **GitHub Pages** (`framefilter.github.io/keyroost-flatpak` or a branch of
     the repo) — free, already in the project's orbit. Caveat: GitHub Pages has
     a soft ~1 GB repo / 100 GB-month bandwidth guidance; an OSTree repo with
     history can grow, so prune old commits or host the repo elsewhere if it
     gets large.
   - **A GitHub Release asset** — publish a single-file `.flatpak` bundle
     (`flatpak build-bundle`) attached to the release. Simpler, but loses the
     auto-update/delta benefit (users re-download the whole bundle). Good as a
     fallback / first cut.
4. Ship a `.flatpakrepo` file (a small INI pointing at the repo URL + GPG key)
   so users add the remote with one command:
   `flatpak remote-add --if-not-exists keyroost https://…/keyroost.flatpakrepo`
   then `flatpak install keyroost io.github.framefilter.keyroost`.

`flat-manager` (Flathub's own backend) is the heavyweight option — a real
service with a token API and delta generation. **Recommendation: do NOT start
with flat-manager.** A static OSTree repo published from CI to GitHub Pages (or
a release bundle) covers a single-app project with no operational burden. Revisit
flat-manager only if you end up shipping many apps/branches.

### Runtime / tooling versions (web-verified June 2026)

- **Runtime:** `org.freedesktop.Platform` / `org.freedesktop.Sdk`. Current
  stable major is **`25.08`** (released 2026; `24.08` is still maintained — each
  branch gets a ~2-year support window, new major every August). The draft
  manifest pins `25.08`; `24.08` is a safe more-conservative alternative.
  *(Verified: freedesktop-sdk releases + Flatpak "Available Runtimes" docs.)*
- **Rust SDK extension:** `org.freedesktop.Sdk.Extension.rust-stable`
  (matching the runtime branch). This is how the official flatpak-cargo example
  builds Rust; it puts `cargo`/`rustc` on `/usr/lib/sdk/rust-stable/bin`.
- **flatpak-builder:** any 1.2+; modern distros ship 1.4.x. The manifest format
  is stable across these.
- **Offline cargo sources:** `flatpak-cargo-generator.py` from
  [flatpak/flatpak-builder-tools](https://github.com/flatpak/flatpak-builder-tools/tree/master/cargo).
  Flatpak builds run with **no network**, so every crate must be pre-declared.
  Generate the sources file **once per `Cargo.lock` change**:

  ```bash
  # one-time: clone the tools, install poetry v2, enter the cargo/ dir
  git clone https://github.com/flatpak/flatpak-builder-tools
  cd flatpak-builder-tools/cargo
  poetry install && poetry env activate     # poetry v2 syntax
  # then, against THIS repo's lockfile:
  python3 flatpak-cargo-generator.py /path/to/keyroost/Cargo.lock \
      -o /path/to/keyroost/packaging/flatpak/cargo-sources.json
  ```

  The generated `cargo-sources.json` (large, machine-generated) is referenced as
  a `sources:` entry in the manifest. **It is intentionally NOT committed in
  this draft** — it must be regenerated whenever `Cargo.lock` changes, and
  checking in a stale one is worse than absent. See the manifest's TODO.

### PC/SC + HID handling in the sandbox

The freedesktop runtime ships **no `libpcsclite`** and there is no `pcscd`
inside the sandbox. Two pieces solve this:

1. **Bundle the pcsc-lite *client* library** as its own build module *before*
   the cargo module, so the build/link finds `libpcsclite.so` and the runtime
   loads it. Ship the `.so` (and headers for the build) — **not** the `pcscd`
   daemon. The draft manifest builds pcsc-lite with
   `--disable-libsystemd --disable-polkit` and (ideally)
   `--enable-libudev=no`, producing just the client lib + `libpcscspy` we don't
   need. *(TODO for maintainer: confirm the exact `./configure` flags that yield
   a client-only build on the pinned pcsc-lite version — the upstream flag names
   have drifted across pcsc-lite 1.9/2.x; pin a known version and verify.)*
2. **Expose the host pcscd socket** via finish-args. `--socket=pcsc` is a
   first-class Flatpak socket (confirmed in the Flatpak command reference: the
   `--socket=` value list includes `pcsc`). It bind-mounts the host's pcscd
   socket into the sandbox so the bundled client lib talks to the host daemon.

FIDO HID needs raw device access:

- `--device=all` exposes `/dev/hidraw*` (the device list is
  `dri|input|usb|kvm|shm|all`; `all` is the documented way to reach arbitrary
  devices incl. hidraw — there is no finer-grained `hidraw` token).
- `--filesystem=/run/udev:ro` lets the HID enumeration read udev's device
  database (sysfs walking + udev metadata). *(TODO: verify on hardware whether
  keyroost-hid actually needs /run/udev, or whether `--device=all` alone +
  `/sys` access from the runtime suffices. keyroost-hid reads sysfs directly,
  so this may be belt-and-suspenders — confirm by testing with and without.)*

The full draft `finish-args` (in the manifest) is:

```yaml
finish-args:
  - --socket=wayland             # GUI
  - --socket=fallback-x11        # GUI on X11
  - --share=ipc                  # X11 shared memory
  - --device=dri                 # GPU for egui/glow
  - --device=all                 # hidraw for FIDO   (TODO: can this be narrowed?)
  - --socket=pcsc                # host pcscd socket for smart-card applets
  - --filesystem=/run/udev:ro    # udev device db for HID enumeration (TODO verify needed)
  - --filesystem=xdg-config/keyroost:create   # keys.json friendly-name registry
```

> **Privacy/scope note:** `--device=all` + `--socket=pcsc` is a broad grant
> (all devices + all the user's smart cards). That is inherent to a security-key
> tool and matches what Yubico Authenticator requests, but call it out in the
> metainfo so users understand it.

### Desktop file, icon, metainfo

Flatpak requires three exported assets, all keyed to the app-id:

- `packaging/flatpak/io.github.framefilter.keyroost.desktop` — the launcher.
- `packaging/flatpak/io.github.framefilter.keyroost.metainfo.xml` — AppStream
  metadata (name, summary, description, license, categories, screenshots).
  Required for the app to appear correctly and for
  `flatpak build-update-repo --update-appstream` to index it.
- An **icon** at `…/share/icons/hicolor/<size>/apps/io.github.framefilter.keyroost.png`
  (or `scalable/apps/…svg`). **keyroost has no icon asset in the repo today**
  (`find` for `*.png`/`*.svg` outside test fixtures returns nothing). The draft
  references `io.github.framefilter.keyroost.svg`; the maintainer must supply a
  real icon — see decisions list. This same icon is reused by the AppImage.

Drafts for the desktop file and metainfo are in `packaging/flatpak/`.

### Build commands (local test)

```bash
cd packaging/flatpak
# 1. regenerate cargo-sources.json (see above) from the repo Cargo.lock
# 2. build into a local repo
flatpak-builder --force-clean --repo=../repo build-dir \
    io.github.framefilter.keyroost.yml
# 3. install + run the just-built app to test
flatpak-builder --user --install --force-clean build-dir \
    io.github.framefilter.keyroost.yml
flatpak run io.github.framefilter.keyroost
```

### Publish / host mechanism

```bash
# regenerate repo metadata, GPG-sign (recommended)
flatpak build-update-repo --update-appstream --gpg-sign=<KEYID> ../repo
# export the one-line install descriptor for users
# (a .flatpakrepo INI: Title, Url=<host>/repo, GPGKey=<base64 pubkey>)
# then upload ../repo to GitHub Pages / static host (rsync, gh-pages action, etc.)
```

> **Do NOT auto-publish from CI in this draft.** A future workflow could run the
> build on tag, but per the task this is intentionally left as a manual runbook
> only. When/if automated, it should be a *separate* workflow file, not an edit
> to `release.yml`/`publish.yml`.

### Known limitations

- Auto-update only works for the OSTree-repo path, not the single-file bundle.
- GPG signing key management is the maintainer's responsibility (a *repo*
  signing key, unrelated to commit-signing keys).
- The sandbox cannot run `pcscd`; if the host has no pcscd running, the
  smart-card applets fail (FIDO HID still works). Document this for users.
- First end-to-end run is **unverified on hardware** — every "TODO verify"
  above needs a real Molto2 + FIDO key test before this ships.

---

## Target 2 — AppImage

### How it works

An AppImage is a self-mounting SquashFS image: a single executable file that,
when run, mounts itself via FUSE and launches the bundled app. It bundles the
GUI binary plus the shared libraries it needs, so it runs across glibc-based
distros without installation. We bundle the **GUI (`keyroost`)** — the AppImage
format is GUI-app-oriented (desktop file + icon are mandatory). The CLI is
better served by the musl static binary (Target 3) or the existing release
tarballs.

### Tooling

- **linuxdeploy** (`linuxdeploy/linuxdeploy`) — builds and maintains the AppDir,
  bundles dependent `.so`s, and (via its appimage plugin) produces the final
  AppImage. Use the continuous-release `linuxdeploy-x86_64.AppImage` +
  `linuxdeploy-plugin-appimage-x86_64.AppImage`.
- **appimagetool** — what the appimage plugin calls under the hood; can be used
  directly if you prefer to assemble the AppDir by hand.
- The build script is `packaging/appimage/build-appimage.sh` (draft).

### FUSE requirement

AppImages mount via **libfuse**. Type-2 AppImages historically needed
**FUSE 2** (`libfuse.so.2`) on the *running* machine; many current distros ship
only FUSE 3, so users may need `fuse` / `libfuse2` installed, or must run with
`--appimage-extract-and-run` (no FUSE needed, extracts to a temp dir). Newer
appimagetool/runtime versions can target a FUSE3-capable static runtime. Document
both the `libfuse2` install hint and the `--appimage-extract-and-run` fallback
for users. *(TODO: pick and pin which appimagetool/runtime version, and state
the exact FUSE story for that version — this has changed recently and should be
verified against the version you ship.)*

### PC/SC + HID handling

- **PC/SC:** an AppImage has **no sandbox** — the bundled binary runs as the
  user against the host. It uses the **host `pcscd`** directly through the
  host's `/run/pcscd/pcscd.comm` socket; no socket plumbing needed. The open
  question is whether to **bundle `libpcsclite.so`** in the AppDir or rely on
  the host's. Recommendation: **bundle it** (linuxdeploy will pull it in as a
  dependency of the keyroost binary) so the AppImage is self-contained on
  systems where pcsc-lite's *client lib* isn't installed even though pcscd is
  reachable — but verify the bundled client lib version is protocol-compatible
  with a range of host pcscd versions (the PC/SC client/daemon wire protocol is
  stable, so this is low-risk; confirm).
- **HID:** pure-Rust sysfs/hidraw — works directly against the host. The user
  still needs the udev rules (`udev/70-keyroost-fido.rules`) for non-root hidraw
  access; the AppImage cannot install udev rules itself. Document this.

### Build commands

See `packaging/appimage/build-appimage.sh`. Outline:

```bash
cargo build --release -p keyroost           # build the GUI binary (glibc)
# stage AppDir, copy binary + desktop + icon, let linuxdeploy bundle libs:
linuxdeploy --appdir AppDir \
    --executable target/release/keyroost \
    --desktop-file packaging/flatpak/io.github.framefilter.keyroost.desktop \
    --icon-file <icon.png> \
    --output appimage
```

(The desktop file + icon are **reused from the Flatpak drafts** — same app-id,
same metadata.)

### Publish mechanism

Attach `keyroost-x86_64.AppImage` (+ its `.zsync` for delta updates, optional)
as a **GitHub Release asset**, alongside the existing tarballs. `release.yml`
already publishes release assets; a future step *could* add the AppImage, but
**this draft does not modify `release.yml`** — the script is run manually for
now. Note Token2 already ships an AppImage of their OEM edition, so the format
is proven for this app.

### Known limitations

- glibc-based: built on an **old** glibc (build in an old-baseline container,
  e.g. an older Ubuntu LTS) or the AppImage only runs on systems with glibc ≥
  the build machine's. This is the classic AppImage portability footgun.
- FUSE dependency on the user's machine (see above).
- No auto-update unless you add `.zsync` + an AppImageUpdate-compatible URL.
- GUI-only by design; CLI users get the musl binary or `cargo install`.

---

## Target 3 — musl static build

### Recommendation up front

**Build only the CLI (`keyroostctl`) as a musl static binary. Do NOT attempt a
musl static GUI.** Rationale below. The GUI's portability story is the AppImage
(Target 2); musl is the *fully-static, dependency-free CLI* story.

### Why CLI-only

`eframe`/`egui` link X11/Wayland/GL libraries (`libxkbcommon`, `libwayland`,
`libxcb`, `libGL`, …) that are **dynamically loaded at runtime** and are not
meaningfully static-linkable. A "static musl GUI" would still `dlopen` the host's
graphics stack, defeating the point and adding a fragile musl-vs-glibc-graphics
mismatch. The CLI, by contrast, has a small, mostly-pure-Rust dependency surface
— its only non-Rust link is `libpcsclite`.

### The libpcsclite wrinkle (the whole problem)

The `keyroostctl` CLI links `libpcsclite` via the `pcsc` crate → `pcsc-sys`,
which links the C library at build time (pkg-config / linker, **no dlopen
feature** in the published crate — *verified against the pcsc-rust README: it's
a direct FFI binding through `pcsc-sys`*). pcsc-lite is glibc-oriented. Under
`x86_64-unknown-linux-musl` (a fully-static target) you cannot dynamically link
a glibc `libpcsclite` into a static-musl binary; the realistic options are:

1. **Static-link a musl-built `libpcsclite.a`.** Cross-compile pcsc-lite itself
   against musl and link it statically. Then the binary is truly static and
   speaks PC/SC. *Caveat:* pcsc-lite's client still talks to the host pcscd over
   a Unix socket at runtime — static linking the *client lib* is fine, the
   *daemon* is always the host's. **This is the recommended path** if PC/SC is
   wanted in the musl build. *(TODO: not web-verifiable in the time available —
   no off-the-shelf recipe found for building libpcsclite against musl. Needs a
   spike: build pcsc-lite with a musl toolchain, confirm `pcsc-sys` finds the
   static lib via `PCSC_LIB_DIR`/pkg-config, link, and smoke-test against a host
   pcscd. Flag as unverified.)*

2. **Drop PC/SC; ship a FIDO-only musl CLI.** Build `keyroostctl` with PC/SC
   compiled out (would require a cargo *feature* to make the `pcsc`/transport
   path optional — **which does not exist today** and would touch `Cargo.toml`,
   so it's out of scope for these no-dependency-change drafts). The pure-Rust
   `keyroost-hid`/`keyroost-ctap` FIDO path has no C deps and musl-links cleanly.
   This yields a static FIDO-only binary but **loses the Molto2/OATH/OpenPGP/PIV
   applets** (all PC/SC). Probably not worth it as the *primary* musl artifact.

3. **`x86_64-unknown-linux-musl` with `-C target-feature=-crt-static`** — a
   "musl but dynamically linked" build. Note: with `-crt-static` off, the musl
   target has historically ended up linking glibc anyway (known rust-lang
   issue), so this is **not** a clean portability win and is **not recommended**.

**Recommendation:** pursue option 1 (static musl CLI with a musl-built
`libpcsclite.a`) and treat it as a hardening spike; fall back to documenting
option 2 only if option 1 proves impractical. Either way, the musl artifact is
the **CLI**, and the GUI stays on glibc + AppImage.

### Build invocation (option 1 skeleton)

```bash
rustup target add x86_64-unknown-linux-musl
# point pcsc-sys at a musl-built static libpcsclite (built separately):
export PCSC_LIB_DIR=/opt/musl-pcsclite/lib       # contains libpcsclite.a
export PCSC_LIB_NAME=pcsclite
export RUSTFLAGS="-C target-feature=+crt-static"
cargo build --release --target x86_64-unknown-linux-musl -p keyroostctl
# result: target/x86_64-unknown-linux-musl/release/keyroostctl  (static)
file target/x86_64-unknown-linux-musl/release/keyroostctl   # expect: statically linked
```

*(TODO: `PCSC_LIB_DIR`/`PCSC_LIB_NAME` are the conventional pcsc-sys overrides;
confirm the exact env var names against the `pcsc-sys` version in `Cargo.lock`
— they are build-script specific and unverified here.)*

A reproducible path is to build inside a musl container
(e.g. `messense/rust-musl-cross` or the official musl images) that already has a
musl cross toolchain, then build libpcsclite there. See
`packaging/musl/README.md` for the expanded runbook.

### Known limitations

- PC/SC under musl is **unverified** (the central open question — see TODO above).
- Still needs a **host pcscd** at runtime (static linking only removes the
  *build/link* dep, not the daemon).
- FIDO HID needs host udev rules for non-root access, same as every target.
- GUI not covered (by design).

---

## Cross-target summary

| | Flatpak (self-host) | AppImage | musl static |
|---|---|---|---|
| Binary | GUI (+CLI optional) | GUI | **CLI only** |
| PC/SC | bundle client lib + `--socket=pcsc` to host pcscd | host pcscd (bundle client lib) | static musl libpcsclite (**unverified**) or FIDO-only |
| FIDO HID | `--device=all` + `/run/udev:ro` | host hidraw + host udev rules | host hidraw + host udev rules |
| Auto-update | yes (OSTree repo) | optional (.zsync) | no |
| Host needs pcscd | yes | yes | yes |
| glibc portability | n/a (runtime) | build on old glibc | fully static (no glibc) |
| Verified on hardware | **no** | **no** | **no** |

---

## Decisions

1. **App-id (reverse-DNS).** **DECIDED: `io.github.framefilter.keyroost`** (matches
   `framefilter.github.io/keyroost` + the GitHub org).
2. **Where to host the Flatpak repo.** **DECIDED:** self-hosted **OSTree repo in a
   dedicated repo `framefilter/keyroost-flatpak`** served by its own GitHub Pages
   (`framefilter.github.io/keyroost-flatpak/`, auto-update) **PLUS** a single-file
   `.flatpak` bundle attached to each release (offline fallback). **NOT Flathub**;
   not flat-manager. (A separate repo because this repo's `main` requires
   verified-signed commits a CI bot can't make — see setup step 3.)
3. **AppImage.** **DECIDED:** build the GUI AppImage and attach it to each release.
4. **Whether/when to automate in CI.** **DECIDED:** automated in the *new*
   `.github/workflows/linux-bundles.yml` (separate from `release.yml`/`publish.yml`).
5. **Flatpak repo GPG signing key.** *Open (recommended).* Sign via the
   `FLATPAK_GPG_KEY` + `FLATPAK_GPG_KEY_ID` secrets (setup step 4). Unset = repo
   published unsigned, signing steps no-op. Maintainer to decide whether to enable.
6. **Icon asset.** *Open (REQUIRED).* keyroost has **no icon**. Supply
   `packaging/icons/io.github.framefilter.keyroost.svg` + `-256.png`
   (see `icons/README.md`). Separate design effort.
7. **Auto-update repo + token.** *Open (REQUIRED action).* Create
   `framefilter/keyroost-flatpak`, enable its Pages (Deploy from a branch, `/`
   root), place the descriptors, and add the `FLATPAK_REPO_TOKEN` secret — setup
   step 3. The main repo's Pages/Learn site is untouched.
8. **This doc's filename.** *Open.* Keep as `packaging/LINUX-BUNDLES.md`, or
   promote to `packaging/README.md` (would need to merge with the existing
   release-fanout README)?
9. **musl scope — OUT OF SCOPE / NOT DECIDED.** [Target 3](#target-3--musl-static-build)
   is documentation only and not wired into any workflow. Revisit separately.
10. **freedesktop runtime version** — *Open.* Manifest pins `25.08` (latest);
    `24.08` is the conservative alternative. The Flatpak CI container image
    (`ghcr.io/flathub-infra/flatpak-github-actions:freedesktop-25.08`) must match
    whatever the manifest pins.
11. **Flatpak `--device=all` breadth.** *Open.* Acceptable, or narrow once
    hardware testing shows what's actually required?
12. **Bundle vs rely-on-host for `libpcsclite`** in the AppImage (recommend
    bundle) and the pcsc-lite version to pin everywhere.

## Claims to double-check (could not fully web-verify)

- **musl + libpcsclite static link** — no off-the-shelf recipe found; the whole
  Target-3 PC/SC path is an unverified spike.
- **`pcsc-sys` env-var names** (`PCSC_LIB_DIR`/`PCSC_LIB_NAME`) — conventional
  but version-specific; verify against the locked `pcsc-sys`.
- **pcsc-lite client-only `./configure` flags** — flag names drift across
  pcsc-lite versions; pin a version and verify.
- **AppImage FUSE2-vs-FUSE3 story** — changed recently; verify against the exact
  appimagetool/runtime version you ship.
- **Whether `--filesystem=/run/udev:ro` is actually needed** for keyroost-hid in
  the Flatpak sandbox — needs a hardware test.
- Everything is **unverified on real hardware** (Molto2 + a FIDO key) end-to-end.
