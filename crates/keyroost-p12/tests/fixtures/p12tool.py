#!/usr/bin/env python3
"""Small PKCS#12 re-encoders for the test fixtures (standard library only).

  p12tool.py indefinite IN OUT          re-wrap IN in BER indefinite lengths
  p12tool.py merge PASSWORD OUT A B     join the entries of A and B (same password)
  p12tool.py full PASSWORD IN OUT       indefinite lengths everywhere, chunked
                                        OCTET STRINGs, MAC recomputed

Both modes keep the MAC valid: `indefinite` leaves the MAC'd bytes untouched,
`merge` recomputes the MAC with the PKCS#12 key derivation (RFC 7292 B.2).
"""
import hashlib
import hmac
import sys


def read(buf, pos=0):
    tag = buf[pos]
    n = buf[pos + 1]
    pos += 2
    if n & 0x80:
        k = n & 0x7F
        n = int.from_bytes(buf[pos:pos + k], "big")
        pos += k
    return tag, buf[pos:pos + n], pos + n


def children(buf):
    out, pos = [], 0
    while pos < len(buf):
        tag, val, pos2 = read(buf, pos)
        out.append((tag, val, buf[pos:pos2]))
        pos = pos2
    return out


def der(tag, val):
    n = len(val)
    if n < 0x80:
        h = bytes([tag, n])
    else:
        b = n.to_bytes((n.bit_length() + 7) // 8, "big")
        h = bytes([tag, 0x80 | len(b)]) + b
    return h + val


def parse(path):
    """Return (authsafe_bytes, [digest_info, salt, iterations], pfx_children)."""
    raw = open(path, "rb").read()
    _, pfx, _ = read(raw)
    parts = children(pfx)               # version, ContentInfo, MacData
    oid, wrapped = children(parts[1][1])
    _, inner, _ = read(wrapped[1])      # [0] -> OCTET STRING
    return inner, children(parts[2][1]), parts


def kdf(hashname, pw, salt, ident, iters, outlen):
    h = hashlib.new(hashname)
    u, v = h.digest_size, 64
    def fill(d):
        if not d:
            return b""
        total = v * ((len(d) + v - 1) // v)
        return (d * (total // len(d) + 1))[:total]

    i = bytearray(fill(salt) + fill(pw))
    out = b""
    while len(out) < outlen:
        a = hashlib.new(hashname, bytes([ident]) * v + bytes(i)).digest()
        for _ in range(iters - 1):
            a = hashlib.new(hashname, a).digest()
        out += a
        b = (a * ((v + u - 1) // u))[:v]
        bi = int.from_bytes(b, "big") + 1
        for j in range(0, len(i), v):
            blk = (int.from_bytes(i[j:j + v], "big") + bi) % (1 << (8 * v))
            i[j:j + v] = blk.to_bytes(v, "big")
    return out[:outlen]


def bmp(pw):
    return pw.encode("utf-16-be") + b"\x00\x00"


def indefinite(src, dst):
    inner, _, parts = parse(src)
    oid = children(parts[1][1])[0][2]
    chunks = b"".join(der(0x04, inner[i:i + 200]) for i in range(0, len(inner), 200))
    ci = b"\x30\x80" + oid + b"\xa0\x80" + b"\x24\x80" + chunks + b"\x00\x00" * 3
    open(dst, "wb").write(b"\x30\x80" + parts[0][2] + ci + parts[2][2] + b"\x00\x00")


def remac(password, ma, safe):
    """MacData for `safe` with the algorithm, salt and iterations of `ma`."""
    digest_info, salt, iters = ma
    alg_id = children(digest_info[1])[0]
    name = {bytes.fromhex("608648016503040201"): "sha256", bytes.fromhex("2b0e03021a"): "sha1"}[
        children(alg_id[1])[0][1]
    ]
    count = int.from_bytes(iters[1], "big")
    key = kdf(name, bmp(password), salt[1], 3, count, hashlib.new(name).digest_size)
    digest = hmac.new(key, safe, name).digest()
    return der(0x30, der(0x30, alg_id[2] + der(0x04, digest)) + der(0x04, salt[1]) + der(0x02, iters[1]))


def chunked(data, tag_prefix=b"\x24\x80"):
    """A constructed OCTET STRING (indefinite length) of small chunks."""
    return tag_prefix + b"".join(der(0x04, data[i:i + 7]) for i in range(0, len(data), 7)) + b"\x00\x00"


def ber(buf):
    """Re-encode DER elements with indefinite lengths; octet strings chunked."""
    out = b""
    for tag, val, raw in children(buf):
        if tag & 0x20:
            out += bytes([tag, 0x80]) + ber(val) + b"\x00\x00"
        elif tag == 0x04:
            out += chunked(val)
        elif tag == 0x80:           # implicit [0] OCTET STRING (encrypted content)
            out += chunked(val, b"\xa0\x80")
        else:
            out += raw
    return out


def full(password, src, dst):
    inner, ma, parts = parse(src)
    infos = []
    for tag, val, raw in children(read(inner)[1]):
        oid, wrapper = children(val)
        if oid[1] == bytes.fromhex("2a864886f70d010701"):          # data
            sc = read(wrapper[1])[1]                                 # OCTET STRING content
            infos.append(b"\x30\x80" + oid[2] + b"\xa0\x80" + chunked(ber(sc)) + b"\x00\x00" * 2)
        else:
            infos.append(ber(raw))
    safe = b"\x30\x80" + b"".join(infos) + b"\x00\x00"
    ci = b"\x30\x80" + children(parts[1][1])[0][2] + b"\xa0\x80" + chunked(safe) + b"\x00\x00" * 2
    mac = ber(remac(password, ma, safe))
    open(dst, "wb").write(b"\x30\x80" + parts[0][2] + ci + mac + b"\x00\x00")


def merge(password, dst, a, b):
    ia, ma, _ = parse(a)
    ib, _, _ = parse(b)
    safe = der(0x30, b"".join(c[2] for c in children(read(ia)[1])) + b"".join(c[2] for c in children(read(ib)[1])))
    mac = remac(password, ma, safe)
    ci = der(0x30, bytes.fromhex("06092a864886f70d010701") + der(0xA0, der(0x04, safe)))
    open(dst, "wb").write(der(0x30, b"\x02\x01\x03" + ci + mac))


if __name__ == "__main__":
    if sys.argv[1] == "indefinite":
        indefinite(sys.argv[2], sys.argv[3])
    elif sys.argv[1] == "merge":
        merge(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])
    elif sys.argv[1] == "full":
        full(sys.argv[2], sys.argv[3], sys.argv[4])
    else:
        sys.exit("unknown mode")
