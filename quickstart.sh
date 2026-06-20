#!/usr/bin/env bash
set -euo pipefail

if ! command -v cargo >/dev/null 2>&1; then
    if command -v brew >/dev/null 2>&1; then
        brew install -y rust
    elif command -v apt >/dev/null 2>&1; then
        sudo apt update && sudo apt install -y cargo
    elif command -v pacman >/dev/null 2>&1; then
        sudo pacman -S --needed cargo
    elif command -v dnf >/dev/null 2>&1; then
        sudo dnf install -y cargo
    else
        printf "No supported package manager found\n" >&2
        exit 1
    fi
fi
cargo install cargo-binstall cargo-update && cargo binstall -y keyroost keyroostctl
printf "\nSuccessfully installed. Run \`keyroost\` for the GUI and \`keyroostctl\` for the CLI.
Run \`cargo install-update -a\` to update all installed cargo packages.\n"
