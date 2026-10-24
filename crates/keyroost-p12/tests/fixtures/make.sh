#!/usr/bin/env bash
# Regenerates every .p12 / .key.der / .crt.der in this folder (see README.md).
# Needs OpenSSL 3 with the legacy provider and python3. Output is throwaway
# test material; keys differ on each run, so re-running changes the files.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
cd "$work"

PW=keyroost-test
DAYS=3650

genkey() { # name algorithm-args...
    local name=$1
    shift
    openssl genpkey "$@" -out "$name.key" 2>/dev/null
    openssl pkey -in "$name.key" -pubout -out "$name.pub"
}

# Certificate for $1's public key, issued by issuer $2 (name of a .crt/.key pair).
issue() {
    openssl x509 -new -force_pubkey "$1.pub" -subj "/CN=$1" \
        -CA "$2.crt" -CAkey "$2.key" -days "$DAYS" -out "$1.crt" 2>/dev/null
}

# Root and intermediate CAs.
genkey ca -algorithm EC -pkeyopt ec_paramgen_curve:P-256
openssl req -new -x509 -key ca.key -subj /CN=ca -days "$DAYS" -out ca.crt
genkey inter -algorithm EC -pkeyopt ec_paramgen_curve:P-256
issue inter ca
cat inter.crt ca.crt >chain-extra.crt

# Leaf keys.
genkey rsa2048 -algorithm RSA -pkeyopt rsa_keygen_bits:2048
genkey rsa4096 -algorithm RSA -pkeyopt rsa_keygen_bits:4096
genkey p256 -algorithm EC -pkeyopt ec_paramgen_curve:P-256
genkey p384 -algorithm EC -pkeyopt ec_paramgen_curve:P-384
genkey ed25519 -algorithm ED25519
genkey x25519 -algorithm X25519
genkey rsae3 -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -pkeyopt rsa_keygen_pubexp:3
genkey second -algorithm EC -pkeyopt ec_paramgen_curve:P-256
for k in rsa2048 rsa4096 p256 p384 ed25519 x25519 rsae3 second; do issue "$k" ca; done
# Chain leaf is issued by the intermediate.
genkey leaf -algorithm RSA -pkeyopt rsa_keygen_bits:2048
issue leaf inter

# DER copies for comparison: PKCS#8 key and leaf certificate.
der() { # source-name target-base
    openssl pkcs8 -topk8 -nocrypt -in "$1.key" -outform DER -out "$here/$2.key.der"
    openssl x509 -in "$1.crt" -outform DER -out "$here/$2.crt.der"
}

export_p12() { # target-base key-name extra openssl args...
    local base=$1 k=$2
    shift 2
    openssl pkcs12 -export -inkey "$k.key" -in "$k.crt" -passout "pass:$PW" \
        -out "$here/$base.p12" "$@"
}

export_p12 rsa2048-modern rsa2048;           der rsa2048 rsa2048-modern
export_p12 rsa2048-legacy rsa2048 -legacy;   der rsa2048 rsa2048-legacy
export_p12 rsa4096-modern rsa4096;           der rsa4096 rsa4096-modern
export_p12 p256-modern p256;                 der p256 p256-modern
export_p12 p384-legacy p384 -legacy;         der p384 p384-legacy
export_p12 ed25519-modern ed25519;           der ed25519 ed25519-modern
export_p12 x25519-modern x25519;             der x25519 x25519-modern
export_p12 rsa-e3 rsae3;                     der rsae3 rsa-e3
export_p12 rsa2048-chain leaf -certfile chain-extra.crt; der leaf rsa2048-chain

# Key only, no certificates.
openssl pkcs12 -export -nocerts -inkey rsa2048.key -passout "pass:$PW" \
    -out "$here/key-only.p12"
openssl pkcs8 -topk8 -nocrypt -in rsa2048.key -outform DER -out "$here/key-only.key.der"

# Empty password.
openssl pkcs12 -export -inkey p256.key -in p256.crt -passout pass: \
    -out "$here/empty-password.p12"
der p256 empty-password

# Two entries (names "first" and "second"), same password. OpenSSL exports one
# key per file, so the two single-entry files are joined and re-MACed.
openssl pkcs12 -export -inkey rsa2048.key -in rsa2048.crt -name first \
    -passout "pass:$PW" -out one.p12
openssl pkcs12 -export -inkey second.key -in second.crt -name second \
    -passout "pass:$PW" -out two.p12
PYTHONDONTWRITEBYTECODE=1 python3 "$here/p12tool.py" merge "$PW" "$here/two-entries.p12" one.p12 two.p12
der rsa2048 two-entries
openssl pkcs8 -topk8 -nocrypt -in second.key -outform DER -out "$here/two-entries.key2.der"
openssl x509 -in second.crt -outform DER -out "$here/two-entries.crt2.der"

# The same file as rsa2048-modern with BER indefinite lengths and a chunked
# AuthenticatedSafe; the MAC is unchanged.
PYTHONDONTWRITEBYTECODE=1 python3 "$here/p12tool.py" indefinite "$here/rsa2048-modern.p12" "$here/ber-indefinite.p12"
der rsa2048 ber-indefinite

# Fully BER: indefinite lengths at every level and chunked OCTET STRINGs
# throughout (what some Windows and Java exporters write); MAC recomputed.
PYTHONDONTWRITEBYTECODE=1 python3 "$here/p12tool.py" full "$PW" "$here/rsa2048-modern.p12" "$here/ber-full.p12"
der rsa2048 ber-full

# No MAC: one with a shrouded key, one with a plaintext key bag.
export_p12 macless-shrouded rsa2048 -nomac;               der rsa2048 macless-shrouded
export_p12 macless-plain-key rsa2048 -nomac -keypbe NONE; der rsa2048 macless-plain-key

# Sanity: OpenSSL itself opens the re-encoded files.
openssl pkcs12 -in "$here/ber-indefinite.p12" -passin "pass:$PW" -noout
openssl pkcs12 -in "$here/two-entries.p12" -passin "pass:$PW" -noout
openssl pkcs12 -in "$here/ber-full.p12" -passin "pass:$PW" -noout
