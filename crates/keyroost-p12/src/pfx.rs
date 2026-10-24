//! The PFX walk: MAC check, AuthenticatedSafe, SafeContents and bags.
//!
//! The shape is fixed: PFX, AuthenticatedSafe, ContentInfo, SafeContents,
//! SafeBag, attributes. Each level is read once; there is no recursion, and a
//! nested `safeContentsBag` is skipped.

use hmac::{Hmac, Mac as _};
use keyroost_oath::crypto::hmac_sha1;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::ber::{children, read_tlv, Tlv};
use crate::kdf::{bmp_password, pkcs12_kdf, Hash};
use crate::pbe::Work;
use crate::{pbe, P12Error};

/// What a bag holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BagKind {
    /// A private key: PKCS#8 PrivateKeyInfo, decrypted.
    Key,
    /// An X.509 certificate, DER.
    Certificate,
}

/// One key or certificate bag, as found in the file.
pub(crate) struct RawBag {
    pub kind: BagKind,
    pub value: Zeroizing<Vec<u8>>,
    pub local_key_id: Option<Vec<u8>>,
    pub friendly_name: Option<String>,
}

const TAG_INTEGER: u8 = 0x02;
const TAG_OCTET_STRING: u8 = 0x04;
const TAG_OCTET_STRING_CONSTRUCTED: u8 = 0x24;
const TAG_OID: u8 = 0x06;
const TAG_BMP_STRING: u8 = 0x1E;
const TAG_SEQUENCE: u8 = 0x30;
const TAG_SET: u8 = 0x31;
const TAG_CONTEXT_0: u8 = 0xA0;
const TAG_CONTEXT_0_PRIMITIVE: u8 = 0x80;

// DER-encoded OID contents.
const DATA_OID: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01];
const ENCRYPTED_DATA_OID: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x06];
const KEY_BAG_OID: &[u8] = &[
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x0a, 0x01, 0x01,
];
const SHROUDED_KEY_BAG_OID: &[u8] = &[
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x0a, 0x01, 0x02,
];
const CERT_BAG_OID: &[u8] = &[
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x0a, 0x01, 0x03,
];
const X509_CERTIFICATE_OID: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x16, 0x01];
const FRIENDLY_NAME_OID: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x14];
const LOCAL_KEY_ID_OID: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x15];
const PBMAC1_OID: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0e];
const SHA1_OID: &[u8] = &[0x2b, 0x0e, 0x03, 0x02, 0x1a];
const SHA256_OID: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];

/// Same cap as the encryption schemes: a hostile file must not stall us.
const MAX_ITERATIONS: u64 = pbe::MAX_ITERATIONS as u64;

fn bad(what: &'static str) -> P12Error {
    P12Error::Malformed(what)
}

/// An OCTET STRING, primitive or BER-constructed (`read_tlv` has already
/// joined the segments of a constructed one into `value`).
fn is_octets(t: &Tlv<'_>) -> bool {
    t.tag == TAG_OCTET_STRING || t.tag == TAG_OCTET_STRING_CONSTRUCTED
}

fn expect_octets(t: &Tlv<'_>, what: &'static str) -> Result<(), P12Error> {
    if is_octets(t) {
        Ok(())
    } else {
        Err(bad(what))
    }
}

fn expect(t: &Tlv<'_>, tag: u8, what: &'static str) -> Result<(), P12Error> {
    if t.tag == tag {
        Ok(())
    } else {
        Err(bad(what))
    }
}

/// A non-negative INTEGER as `u64`, clamped to `u64::MAX`.
fn uint(t: &Tlv<'_>) -> Result<u64, P12Error> {
    expect(t, TAG_INTEGER, "expected an INTEGER")?;
    match t.value.first() {
        None => return Err(bad("empty INTEGER")),
        Some(b) if b & 0x80 != 0 => return Err(bad("negative INTEGER")),
        _ => {}
    }
    let mut n: u64 = 0;
    for &b in t.value.iter() {
        if n > u64::MAX >> 8 {
            return Ok(u64::MAX);
        }
        n = (n << 8) | u64::from(b);
    }
    Ok(n)
}

/// Re-encode a parsed element as DER-style `tag || length || value` into a
/// buffer that is zeroized on drop (the value may be key material).
fn encode(t: &Tlv<'_>) -> Zeroizing<Vec<u8>> {
    let len = t.value.len();
    let mut out = Zeroizing::new(Vec::with_capacity(len + 6));
    out.push(t.tag);
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let skip = bytes.iter().take_while(|&&b| b == 0).count();
        out.push(0x80 | (bytes.len() - skip) as u8);
        out.extend_from_slice(&bytes[skip..]);
    }
    out.extend_from_slice(&t.value);
    out
}

/// The single element inside an EXPLICIT `[0]` wrapper.
fn explicit_content<'a>(wrapper: &'a Tlv<'a>) -> Result<Tlv<'a>, P12Error> {
    expect(wrapper, TAG_CONTEXT_0, "expected an explicit [0] content")?;
    let mut kids = children(&wrapper.value)?;
    if kids.len() != 1 {
        return Err(bad("explicit [0] holds more than one element"));
    }
    Ok(kids.remove(0))
}

/// Read a PKCS#12 file and return its key and certificate bags.
///
/// The MAC is checked first (a mismatch is `WrongPassword`). With no password,
/// or an empty one, both the "no password" and the "empty string" encodings
/// are tried, as other PKCS#12 tools do. A file without a MAC is accepted and
/// relies on the padding check of its encrypted parts, but only if every key
/// comes from an encrypted container. Without a MAC nothing vouches for a
/// plaintext key bag (it could have been swapped), so such a file is refused.
///
/// All key derivation (the MAC and every encrypted part, for each password
/// candidate) shares one [`pbe::WORK_BUDGET`].
pub(crate) fn read_bags(der: &[u8], password: Option<&str>) -> Result<Vec<RawBag>, P12Error> {
    read_bags_within(der, password, &mut Work::new())
}

fn read_bags_within(
    der: &[u8],
    password: Option<&str>,
    work: &mut Work,
) -> Result<Vec<RawBag>, P12Error> {
    let (pfx, _) = read_tlv(der)?;
    expect(&pfx, TAG_SEQUENCE, "PFX is not a SEQUENCE")?;
    let parts = children(&pfx.value)?;
    let (version, content_info, mac_data) = match parts.as_slice() {
        [v, c] => (v, c, None),
        [v, c, m] => (v, c, Some(m)),
        _ => return Err(bad("PFX has the wrong number of fields")),
    };
    if uint(version)? != 3 {
        return Err(P12Error::Unsupported("PKCS#12 version"));
    }
    expect(content_info, TAG_SEQUENCE, "PFX content is not a SEQUENCE")?;
    let ci = children(&content_info.value)?;
    let [oid, wrapper] = ci.as_slice() else {
        return Err(bad("PFX content is not (type, content)"));
    };
    if oid.tag != TAG_OID || *oid.value != *DATA_OID {
        return Err(P12Error::Unsupported("PKCS#12 with public-key integrity"));
    }
    let octets = explicit_content(wrapper)?;
    expect_octets(&octets, "PFX content is not an OCTET STRING")?;
    let auth_safe: &[u8] = &octets.value;

    let mac = mac_data.map(parse_mac).transpose()?;

    let candidates: &[Option<&str>] = match password {
        None | Some("") => &[None, Some("")],
        Some(_) => &[password],
    };
    for (i, pw) in candidates.iter().copied().enumerate() {
        let last = i + 1 == candidates.len();
        if let Some(mac) = &mac {
            if !mac.verify(auth_safe, pw, work)? {
                continue;
            }
        }
        match walk_auth_safe(auth_safe, pw, mac.is_some(), work) {
            Err(P12Error::WrongPassword) if !last => continue,
            other => return other,
        }
    }
    Err(P12Error::WrongPassword)
}

struct Mac {
    hash: Hash,
    digest: Vec<u8>,
    salt: Vec<u8>,
    iterations: u32,
}

impl Mac {
    /// Whether the MAC over `data` matches under this password, charging the
    /// key derivation to `work`.
    fn verify(
        &self,
        data: &[u8],
        password: Option<&str>,
        work: &mut Work,
    ) -> Result<bool, P12Error> {
        work.spend(self.iterations)?;
        let pw = bmp_password(password);
        let key = pkcs12_kdf(
            self.hash,
            &pw,
            &self.salt,
            3,
            self.iterations,
            self.hash.output_len(),
        );
        let computed: Vec<u8> = match self.hash {
            Hash::Sha1 => hmac_sha1(&key, data).to_vec(),
            Hash::Sha256 => match Hmac::<Sha256>::new_from_slice(&key) {
                Ok(mut m) => {
                    m.update(data);
                    m.finalize().into_bytes().to_vec()
                }
                Err(_) => return Ok(false),
            },
        };
        Ok(constant_time_eq(&computed, &self.digest))
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn parse_mac(mac_data: &Tlv<'_>) -> Result<Mac, P12Error> {
    expect(mac_data, TAG_SEQUENCE, "MacData is not a SEQUENCE")?;
    let kids = children(&mac_data.value)?;
    let (digest_info, salt, iterations) = match kids.as_slice() {
        [d, s] => (d, s, 1),
        [d, s, i] => (d, s, uint(i)?),
        _ => return Err(bad("MacData has the wrong number of fields")),
    };
    expect(digest_info, TAG_SEQUENCE, "DigestInfo is not a SEQUENCE")?;
    let di = children(&digest_info.value)?;
    let [alg, digest] = di.as_slice() else {
        return Err(bad("DigestInfo is not (algorithm, digest)"));
    };
    expect(alg, TAG_SEQUENCE, "MAC algorithm is not a SEQUENCE")?;
    let alg_kids = children(&alg.value)?;
    let alg_oid = alg_kids.first().ok_or_else(|| bad("empty MAC algorithm"))?;
    expect(alg_oid, TAG_OID, "MAC algorithm has no OID")?;
    let hash = match &*alg_oid.value {
        o if o == PBMAC1_OID => return Err(P12Error::Unsupported("PBMAC1")),
        o if o == SHA1_OID => Hash::Sha1,
        o if o == SHA256_OID => Hash::Sha256,
        _ => return Err(P12Error::Unsupported("MAC algorithm")),
    };
    expect_octets(digest, "MAC digest is not an OCTET STRING")?;
    expect_octets(salt, "MAC salt is not an OCTET STRING")?;
    if iterations == 0 {
        return Err(bad("zero MAC iteration count"));
    }
    if iterations > MAX_ITERATIONS {
        return Err(P12Error::Unsupported("iteration count above 10,000,000"));
    }
    Ok(Mac {
        hash,
        digest: digest.value.to_vec(),
        salt: salt.value.to_vec(),
        iterations: iterations as u32,
    })
}

/// AuthenticatedSafe: a SEQUENCE of ContentInfo, each a `data` or
/// `encryptedData` holding a SafeContents.
fn walk_auth_safe(
    auth_safe: &[u8],
    password: Option<&str>,
    plain_keys_ok: bool,
    work: &mut Work,
) -> Result<Vec<RawBag>, P12Error> {
    let (seq, _) = read_tlv(auth_safe)?;
    expect(&seq, TAG_SEQUENCE, "AuthenticatedSafe is not a SEQUENCE")?;
    let mut bags = Vec::new();
    for info in children(&seq.value)? {
        expect(&info, TAG_SEQUENCE, "ContentInfo is not a SEQUENCE")?;
        let ci = children(&info.value)?;
        let [oid, wrapper] = ci.as_slice() else {
            return Err(bad("ContentInfo is not (type, content)"));
        };
        expect(oid, TAG_OID, "ContentInfo has no type OID")?;
        let content = explicit_content(wrapper)?;
        if *oid.value == *DATA_OID {
            expect_octets(&content, "data content is not an OCTET STRING")?;
            safe_contents(&content.value, password, plain_keys_ok, work, &mut bags)?;
        } else if *oid.value == *ENCRYPTED_DATA_OID {
            let plain = decrypt_encrypted_data(&content, password, work)?;
            safe_contents(&plain, password, true, work, &mut bags)?;
        } else {
            return Err(P12Error::Unsupported("AuthenticatedSafe content type"));
        }
    }
    Ok(bags)
}

/// EncryptedData ::= SEQUENCE { version, EncryptedContentInfo }.
fn decrypt_encrypted_data(
    ed: &Tlv<'_>,
    password: Option<&str>,
    work: &mut Work,
) -> Result<Zeroizing<Vec<u8>>, P12Error> {
    expect(ed, TAG_SEQUENCE, "EncryptedData is not a SEQUENCE")?;
    let kids = children(&ed.value)?;
    let [_version, eci] = kids.as_slice() else {
        return Err(bad("EncryptedData is not (version, content)"));
    };
    expect(eci, TAG_SEQUENCE, "EncryptedContentInfo is not a SEQUENCE")?;
    let parts = children(&eci.value)?;
    let [kind, alg, cipher] = parts.as_slice() else {
        return Err(bad(
            "EncryptedContentInfo is not (type, algorithm, content)",
        ));
    };
    if kind.tag != TAG_OID || *kind.value != *DATA_OID {
        return Err(P12Error::Unsupported("encrypted content type"));
    }
    let ciphertext = implicit_octets(cipher)?;
    pbe::decrypt(alg, &ciphertext, password, work)
}

/// The bytes of an IMPLICIT `[0]` OCTET STRING, primitive or BER-chunked.
fn implicit_octets(t: &Tlv<'_>) -> Result<Vec<u8>, P12Error> {
    match t.tag {
        TAG_CONTEXT_0_PRIMITIVE => Ok(t.value.to_vec()),
        TAG_CONTEXT_0 => {
            let mut out = Vec::new();
            for seg in children(&t.value)? {
                expect_octets(&seg, "chunk is not an OCTET STRING")?;
                out.extend_from_slice(&seg.value);
            }
            Ok(out)
        }
        _ => Err(bad("encrypted content is not an implicit [0] OCTET STRING")),
    }
}

/// SafeContents ::= SEQUENCE OF SafeBag; appends the key and certificate bags.
fn safe_contents(
    data: &[u8],
    password: Option<&str>,
    plain_keys_ok: bool,
    work: &mut Work,
    bags: &mut Vec<RawBag>,
) -> Result<(), P12Error> {
    let (seq, _) = read_tlv(data)?;
    expect(&seq, TAG_SEQUENCE, "SafeContents is not a SEQUENCE")?;
    for bag in children(&seq.value)? {
        if let Some(raw) = safe_bag(&bag, password, plain_keys_ok, work)? {
            bags.push(raw);
        }
    }
    Ok(())
}

/// SafeBag ::= SEQUENCE { bagId, [0] bagValue, SET attributes OPTIONAL }.
/// Bag kinds other than keys and X.509 certificates are skipped.
fn safe_bag(
    bag: &Tlv<'_>,
    password: Option<&str>,
    plain_keys_ok: bool,
    work: &mut Work,
) -> Result<Option<RawBag>, P12Error> {
    expect(bag, TAG_SEQUENCE, "SafeBag is not a SEQUENCE")?;
    let kids = children(&bag.value)?;
    let (id, wrapper, attrs) = match kids.as_slice() {
        [i, w] => (i, w, None),
        [i, w, a] => (i, w, Some(a)),
        _ => return Err(bad("SafeBag has the wrong number of fields")),
    };
    expect(id, TAG_OID, "SafeBag has no type OID")?;
    let value = explicit_content(wrapper)?;
    let (kind, bytes) = if *id.value == *KEY_BAG_OID {
        if !plain_keys_ok {
            return Err(P12Error::Unsupported("file has no integrity check"));
        }
        expect(&value, TAG_SEQUENCE, "key bag is not a SEQUENCE")?;
        (BagKind::Key, encode(&value))
    } else if *id.value == *SHROUDED_KEY_BAG_OID {
        expect(&value, TAG_SEQUENCE, "shrouded key bag is not a SEQUENCE")?;
        let parts = children(&value.value)?;
        let [alg, cipher] = parts.as_slice() else {
            return Err(bad("EncryptedPrivateKeyInfo is not (algorithm, data)"));
        };
        expect_octets(cipher, "encrypted key is not an OCTET STRING")?;
        (
            BagKind::Key,
            pbe::decrypt(alg, &cipher.value, password, work)?,
        )
    } else if *id.value == *CERT_BAG_OID {
        expect(&value, TAG_SEQUENCE, "cert bag is not a SEQUENCE")?;
        let parts = children(&value.value)?;
        let [cert_type, cert_wrapper] = parts.as_slice() else {
            return Err(bad("CertBag is not (type, value)"));
        };
        if cert_type.tag != TAG_OID || *cert_type.value != *X509_CERTIFICATE_OID {
            return Ok(None);
        }
        let cert = explicit_content(cert_wrapper)?;
        expect_octets(&cert, "certificate is not an OCTET STRING")?;
        (BagKind::Certificate, Zeroizing::new(cert.value.to_vec()))
    } else {
        return Ok(None);
    };
    let mut local_key_id = None;
    let mut friendly_name = None;
    if let Some(attrs) = attrs {
        expect(attrs, TAG_SET, "bag attributes are not a SET")?;
        for attr in children(&attrs.value)? {
            expect(&attr, TAG_SEQUENCE, "attribute is not a SEQUENCE")?;
            let ak = children(&attr.value)?;
            let [aid, avals] = ak.as_slice() else {
                return Err(bad("attribute is not (type, values)"));
            };
            expect(aid, TAG_OID, "attribute has no type OID")?;
            expect(avals, TAG_SET, "attribute values are not a SET")?;
            let vals = children(&avals.value)?;
            let Some(first) = vals.first() else { continue };
            if *aid.value == *LOCAL_KEY_ID_OID && is_octets(first) {
                local_key_id = Some(first.value.to_vec());
            } else if *aid.value == *FRIENDLY_NAME_OID && first.tag == TAG_BMP_STRING {
                friendly_name = bmp_to_string(&first.value);
            }
        }
    }
    Ok(Some(RawBag {
        kind,
        value: bytes,
        local_key_id,
        friendly_name,
    }))
}

/// UTF-16BE bytes to a string; `None` when they are not valid UTF-16.
fn bmp_to_string(bytes: &[u8]) -> Option<String> {
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16(&units).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! fx {
        ($n:expr) => {
            include_bytes!(concat!("../tests/fixtures/", $n))
        };
    }

    const PW: Option<&str> = Some("keyroost-test");

    fn bags(p12: &[u8]) -> Vec<RawBag> {
        read_bags(p12, PW).unwrap()
    }

    fn keys(b: &[RawBag]) -> Vec<&RawBag> {
        b.iter().filter(|x| x.kind == BagKind::Key).collect()
    }

    fn certs(b: &[RawBag]) -> Vec<&RawBag> {
        b.iter()
            .filter(|x| x.kind == BagKind::Certificate)
            .collect()
    }

    /// One key bag equal to `key`, and a certificate bag equal to `crt`.
    fn check(p12: &[u8], key: &[u8], crt: &[u8]) {
        let b = bags(p12);
        let k = keys(&b);
        assert_eq!(k.len(), 1);
        assert_eq!(&k[0].value[..], key);
        assert!(certs(&b).iter().any(|c| &c.value[..] == crt));
    }

    macro_rules! same_as_der {
        ($name:ident, $base:literal) => {
            #[test]
            fn $name() {
                check(
                    fx!(concat!($base, ".p12")),
                    fx!(concat!($base, ".key.der")),
                    fx!(concat!($base, ".crt.der")),
                );
            }
        };
    }

    same_as_der!(rsa2048_modern, "rsa2048-modern");
    same_as_der!(rsa2048_legacy, "rsa2048-legacy");
    same_as_der!(rsa4096_modern, "rsa4096-modern");
    same_as_der!(p256_modern, "p256-modern");
    same_as_der!(p384_legacy, "p384-legacy");
    same_as_der!(ed25519_modern, "ed25519-modern");
    same_as_der!(x25519_modern, "x25519-modern");
    same_as_der!(rsa_e3, "rsa-e3");
    same_as_der!(ber_fixture_opens, "ber-indefinite");
    same_as_der!(fully_ber_fixture_opens, "ber-full");
    same_as_der!(macless_file_with_shrouded_key_opens, "macless-shrouded");

    #[test]
    fn macless_file_with_plain_key_is_refused() {
        assert_eq!(
            read_bags(fx!("macless-plain-key.p12"), PW).err(),
            Some(P12Error::Unsupported("file has no integrity check"))
        );
    }

    #[test]
    fn chain_has_leaf_and_two_more_certificates() {
        let p12 = fx!("rsa2048-chain.p12");
        check(
            p12,
            fx!("rsa2048-chain.key.der"),
            fx!("rsa2048-chain.crt.der"),
        );
        assert_eq!(certs(&bags(p12)).len(), 3);
    }

    #[test]
    fn key_only_has_no_certificates() {
        let b = bags(fx!("key-only.p12"));
        assert_eq!(keys(&b).len(), 1);
        assert_eq!(&keys(&b)[0].value[..], &fx!("key-only.key.der")[..]);
        assert!(certs(&b).is_empty());
    }

    #[test]
    fn two_entries_carry_names_and_matching_ids() {
        let b = bags(fx!("two-entries.p12"));
        assert_eq!(keys(&b).len(), 2);
        assert_eq!(certs(&b).len(), 2);
        let mut names: Vec<_> = keys(&b)
            .iter()
            .map(|k| k.friendly_name.clone().unwrap())
            .collect();
        names.sort();
        assert_eq!(names, ["first", "second"]);
        for k in keys(&b) {
            let id = k.local_key_id.as_ref().unwrap();
            let c = certs(&b)
                .into_iter()
                .find(|c| c.local_key_id.as_ref() == Some(id))
                .unwrap();
            assert_eq!(c.friendly_name, k.friendly_name);
        }
        let second = keys(&b)
            .into_iter()
            .find(|k| k.friendly_name.as_deref() == Some("second"))
            .unwrap();
        assert_eq!(&second.value[..], &fx!("two-entries.key2.der")[..]);
    }

    #[test]
    fn wrong_password_is_wrong_password() {
        for f in [
            &fx!("rsa2048-modern.p12")[..],
            &fx!("rsa2048-legacy.p12")[..],
            &fx!("ber-indefinite.p12")[..],
        ] {
            assert_eq!(
                read_bags(f, Some("nope")).err(),
                Some(P12Error::WrongPassword)
            );
            assert_eq!(read_bags(f, None).err(), Some(P12Error::WrongPassword));
        }
    }

    #[test]
    fn empty_password_file_opens_with_none_and_empty() {
        let p12 = fx!("empty-password.p12");
        for pw in [None, Some("")] {
            let b = read_bags(p12, pw).unwrap();
            assert_eq!(&keys(&b)[0].value[..], &fx!("empty-password.key.der")[..]);
        }
        assert_eq!(
            read_bags(p12, Some("x")).err(),
            Some(P12Error::WrongPassword)
        );
    }

    #[test]
    fn legacy_and_modern_rsa2048_yield_same_kinds() {
        let kinds = |p12: &[u8]| bags(p12).iter().map(|b| b.kind).collect::<Vec<_>>();
        assert_eq!(
            kinds(fx!("rsa2048-legacy.p12")),
            kinds(fx!("rsa2048-modern.p12"))
        );
    }

    fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        assert!(content.len() < 0x80);
        let mut v = vec![tag, content.len() as u8];
        v.extend_from_slice(content);
        v
    }

    #[test]
    fn pbmac1_is_unsupported() {
        // PFX v3, empty `data` content, MacData whose algorithm is PBMAC1.
        let pbmac1 = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0e];
        let data_oid = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01];
        let content_info = tlv(
            0x30,
            &[tlv(0x06, &data_oid), tlv(0xA0, &tlv(0x04, &tlv(0x30, &[])))].concat(),
        );
        let alg = tlv(0x30, &[tlv(0x06, &pbmac1), tlv(0x30, &[])].concat());
        let mac = tlv(
            0x30,
            &[
                tlv(0x30, &[alg, tlv(0x04, &[0u8; 4])].concat()),
                tlv(0x04, &[1u8; 4]),
                tlv(0x02, &[1]),
            ]
            .concat(),
        );
        let pfx = tlv(0x30, &[tlv(0x02, &[3]), content_info, mac].concat());
        assert_eq!(
            read_bags(&pfx, PW).err(),
            Some(P12Error::Unsupported("PBMAC1"))
        );
    }

    /// `tag || length || content`, with a long-form length when needed.
    fn tlv_long(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut v = vec![tag];
        let len = content.len();
        if len < 0x80 {
            v.push(len as u8);
        } else {
            let b = (len as u32).to_be_bytes();
            let skip = b.iter().take_while(|&&x| x == 0).count();
            v.push(0x80 | (4 - skip) as u8);
            v.extend_from_slice(&b[skip..]);
        }
        v.extend_from_slice(content);
        v
    }

    /// A MAC-less PFX whose one `data` SafeContents holds `n` shrouded key
    /// bags, each PBES2 (PBKDF2-SHA1, 2048 iterations, AES-128) over a short
    /// plaintext. The bags are not PKCS#8, which `read_bags` does not check.
    fn many_shrouded_bags(n: usize) -> Vec<u8> {
        const ALG: &str = "304906092a864886f70d01050d303c301b06092a864886f70d01050c300e0408010203040506070802020800301d06096086480165030401020410101112131415161718191a1b1c1d1e1f";
        const CT: &str = "12ede7d7d6a368bd63f9f90480fc142fb7f0c6de095d3aa8b0aa6956c63535ab";
        let unhex = |h: &str| -> Vec<u8> {
            (0..h.len() / 2)
                .map(|i| u8::from_str_radix(&h[2 * i..2 * i + 2], 16).unwrap())
                .collect()
        };
        let epki = tlv_long(0x30, &[unhex(ALG), tlv_long(0x04, &unhex(CT))].concat());
        let bag = tlv_long(
            0x30,
            &[tlv_long(0x06, SHROUDED_KEY_BAG_OID), tlv_long(0xA0, &epki)].concat(),
        );
        let safe_contents = tlv_long(0x30, &bag.repeat(n));
        let data_info = |content: &[u8]| {
            tlv_long(
                0x30,
                &[
                    tlv_long(0x06, DATA_OID),
                    tlv_long(0xA0, &tlv_long(0x04, content)),
                ]
                .concat(),
            )
        };
        let auth_safe = tlv_long(0x30, &data_info(&safe_contents));
        tlv_long(0x30, &[tlv(0x02, &[3]), data_info(&auth_safe)].concat())
    }

    #[test]
    fn work_adds_up_across_bags() {
        const PW: Option<&str> = Some("password");
        let p12 = many_shrouded_bags(10);
        let mut work = Work::with_budget(10 * 2048);
        assert_eq!(read_bags_within(&p12, PW, &mut work).unwrap().len(), 10);
        assert_eq!(work.left(), 0);
        // Three bags' worth of budget stops at the fourth, before its KDF.
        assert_eq!(
            read_bags_within(&p12, PW, &mut Work::with_budget(3 * 2048)).err(),
            Some(P12Error::Unsupported(pbe::TOO_MUCH_WORK))
        );
    }

    #[test]
    fn over_budget_file_is_refused_before_its_kdf_runs() {
        // The full budget, all but spent: the first derivation of a file of
        // ten thousand bags is refused without running.
        let p12 = many_shrouded_bags(10_000);
        let mut work = Work::new();
        work.spend(u32::try_from(pbe::WORK_BUDGET - 2047).unwrap())
            .unwrap();
        let started = std::time::Instant::now();
        assert_eq!(
            read_bags_within(&p12, Some("password"), &mut work).err(),
            Some(P12Error::Unsupported(pbe::TOO_MUCH_WORK))
        );
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
    }

    #[test]
    fn both_empty_password_candidates_and_the_mac_are_charged() {
        let p12 = fx!("empty-password.p12");
        let spent = |pw| {
            let mut work = Work::new();
            let got = read_bags_within(p12, pw, &mut work).map(|b| b.len());
            (got, pbe::WORK_BUDGET - work.left())
        };
        // One candidate, a failing MAC: the MAC alone is charged.
        let (got, mac) = spent(Some("x"));
        assert_eq!(got, Err(P12Error::WrongPassword));
        assert!(mac > 0);
        // This file's MAC is for the empty string, the second candidate: the
        // first candidate's failed MAC, the second's, and its bags.
        let (pfx, _) = read_tlv(p12).unwrap();
        let parts = children(&pfx.value).unwrap();
        let ci = children(&parts[1].value).unwrap();
        let octets = explicit_content(&ci[1]).unwrap();
        let mut walk = Work::new();
        walk_auth_safe(&octets.value, Some(""), true, &mut walk).unwrap();
        let bags = pbe::WORK_BUDGET - walk.left();
        assert!(bags > 0);
        for pw in [None, Some("")] {
            let (got, total) = spent(pw);
            assert!(got.is_ok());
            assert_eq!(total, 2 * mac + bags, "{pw:?}");
        }
    }

    #[test]
    fn garbage_is_malformed_not_a_panic() {
        for bad in [
            &b""[..],
            &[0x30][..],
            &[0x30, 0x03, 0x02, 0x01, 0x03][..],
            &[0xFF; 40][..],
        ] {
            assert!(matches!(read_bags(bad, PW), Err(P12Error::Malformed(_))));
        }
    }
}
