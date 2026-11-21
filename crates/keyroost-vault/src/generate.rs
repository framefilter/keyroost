//! Random password generator (same character sets as fidoparole).

use crate::error::VaultError;
use zeroize::Zeroizing;

/// What the generated password may contain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenOptions {
    pub length: usize,
    pub upper: bool,
    pub lower: bool,
    pub digits: bool,
    pub symbols: bool,
}

impl Default for GenOptions {
    fn default() -> Self {
        GenOptions {
            length: 20,
            upper: true,
            lower: true,
            digits: true,
            symbols: true,
        }
    }
}

/// A uniform random password with at least one character of each chosen class.
/// Length is clamped to `max(classes, 4)..=128`; with no class chosen,
/// lowercase is used.
pub fn generate_password(o: &GenOptions) -> Result<Zeroizing<String>, VaultError> {
    const U: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ";
    const L: &[u8] = b"abcdefghijkmnopqrstuvwxyz";
    const D: &[u8] = b"23456789";
    const S: &[u8] = b"!#$%&*+-=?@^_~.,:;";
    let mut classes: Vec<&[u8]> = [(o.upper, U), (o.lower, L), (o.digits, D), (o.symbols, S)]
        .iter()
        .filter(|(on, _)| *on)
        .map(|&(_, s)| s)
        .collect();
    if classes.is_empty() {
        classes.push(L);
    }
    let all: Vec<u8> = classes.iter().flat_map(|c| c.iter().copied()).collect();
    let len = o.length.clamp(classes.len().max(4), 128);
    let mut rng = Rng::new();
    loop {
        let mut pw = Zeroizing::new(Vec::with_capacity(len));
        for _ in 0..len {
            pw.push(all[rng.below(all.len())?]);
        }
        if classes.iter().all(|c| pw.iter().any(|b| c.contains(b))) {
            // Every byte comes from the ASCII sets above.
            return String::from_utf8(std::mem::take(&mut *pw))
                .map(Zeroizing::new)
                .map_err(|_| VaultError::Random);
        }
    }
}

/// Random words drawn from the OS in batches, wiped on drop.
struct Rng {
    buf: Zeroizing<[u8; 256]>,
    pos: usize,
}

impl Rng {
    fn new() -> Self {
        Rng {
            buf: Zeroizing::new([0; 256]),
            pos: 256,
        }
    }

    fn next_u32(&mut self) -> Result<u32, VaultError> {
        if self.pos + 4 > self.buf.len() {
            getrandom::fill(&mut *self.buf).map_err(|_| VaultError::Random)?;
            self.pos = 0;
        }
        let b = &self.buf[self.pos..self.pos + 4];
        self.pos += 4;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Uniform in `0..n` by rejection sampling (no modulo bias). `n` is small
    /// and non-zero.
    fn below(&mut self, n: usize) -> Result<usize, VaultError> {
        let n = n as u32;
        let zone = u32::MAX - (u32::MAX % n);
        loop {
            let r = self.next_u32()?;
            if r < zone {
                return Ok((r % n) as usize);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const U: &str = "ABCDEFGHJKLMNPQRSTUVWXYZ";
    const L: &str = "abcdefghijkmnopqrstuvwxyz";
    const D: &str = "23456789";
    const S: &str = "!#$%&*+-=?@^_~.,:;";

    #[test]
    fn generator_length_and_classes() {
        let o = GenOptions::default();
        let allowed = format!("{U}{L}{D}{S}");
        for _ in 0..1000 {
            let p = generate_password(&o).unwrap();
            assert_eq!(p.len(), 20);
            for set in [U, L, D, S] {
                assert!(p.chars().any(|c| set.contains(c)), "{}", p.len());
            }
            assert!(p.chars().all(|c| allowed.contains(c)));
        }
    }

    #[test]
    fn generator_clamps() {
        let o = |length, u, l, d, s| GenOptions {
            length,
            upper: u,
            lower: l,
            digits: d,
            symbols: s,
        };
        assert_eq!(
            generate_password(&o(2, true, true, true, true))
                .unwrap()
                .len(),
            4
        );
        assert_eq!(
            generate_password(&o(500, true, true, true, true))
                .unwrap()
                .len(),
            128
        );
        let p = generate_password(&o(30, false, false, false, false)).unwrap();
        assert_eq!(p.len(), 30);
        assert!(p.chars().all(|c| L.contains(c)));
    }

    #[test]
    fn single_class_only() {
        let o = GenOptions {
            length: 40,
            upper: false,
            lower: false,
            digits: true,
            symbols: false,
        };
        assert!(generate_password(&o)
            .unwrap()
            .chars()
            .all(|c| D.contains(c)));
    }
}
