use std::borrow::Cow;
use std::borrow::Borrow;
use curv::arithmetic::Modulo;
use curv::BigInt;
use curv::arithmetic::{Integer, One, Samplable, Zero};
use crate::optimized_paillier::{Add, Encrypt, EncryptWithPrecomputeTable, EncryptionKey, Mul, OptimizedPaillier, PowWithPrecomputeTable, PrecomputeTable, RawCiphertext, RawPlaintext};
use crate::optimized_paillier::utils::Randomness;

impl<'m, 'd> Encrypt<EncryptionKey, RawPlaintext<'m>, RawCiphertext<'d>> for OptimizedPaillier {
    fn encrypt(ek: &EncryptionKey, m: RawPlaintext<'m>) -> RawCiphertext<'d> {
        let r = Randomness::sample(ek);
        // rn = hn^r (mod n^2)
        let rn = BigInt::mod_pow(&ek.hn, &r.0, &ek.nn);

        // gm = (1 + m*n) (mod n^2)
        let gm: BigInt = (m.0.borrow() as &BigInt * &ek.n + 1) % &ek.nn;

        let c = (gm * rn) % &ek.nn;

        RawCiphertext(Cow::Owned(c))
    }
}

impl<'m, 'd> EncryptWithPrecomputeTable<EncryptionKey, RawPlaintext<'m>, RawCiphertext<'d>, PrecomputeTable> for OptimizedPaillier {
    fn encrypt_with_precompute_table(precompute_table: &PrecomputeTable, ek: &EncryptionKey, m: RawPlaintext<'m>) -> RawCiphertext<'d> {
        // number of bit(r) = alpha_size
        let r = Randomness::sample(ek);

        // rn = hn^r (mod n^2)
        // use Self::pow() instead of BigInt::mod_pow()
        // so, we replace `let rn = BigInt::mod_pow(&ek.hn, &r.0, &ek.nn);` by
        let rn = Self::pow(precompute_table, &r.0);

        // gm = (1 + m*n) (mod n^2)
        let gm: BigInt = (m.0.borrow() as &BigInt * &ek.n + 1) % &ek.nn;

        let c = (gm * rn) % &ek.nn;

        RawCiphertext(Cow::Owned(c))
    }
}


impl<'c1, 'c2, 'd> Add<EncryptionKey, RawCiphertext<'c1>, RawCiphertext<'c2>, RawCiphertext<'d>>
for OptimizedPaillier
{
    fn add(
        ek: &EncryptionKey,
        c1: RawCiphertext<'c1>,
        c2: RawCiphertext<'c2>,
    ) -> RawCiphertext<'d> {
        let d = (c1.0.borrow() as &BigInt * c2.0.borrow() as &BigInt) % &ek.nn;
        RawCiphertext(Cow::Owned(d))
    }
}

impl<'c, 'm, 'd> Add<EncryptionKey, RawCiphertext<'c>, RawPlaintext<'m>, RawCiphertext<'d>>
for OptimizedPaillier
{
    fn add(ek: &EncryptionKey, c: RawCiphertext<'c>, m: RawPlaintext<'m>) -> RawCiphertext<'d> {
        let c1 = c.0.borrow() as &BigInt;
        let c2 = (m.0.borrow() as &BigInt * &ek.n + 1) % &ek.nn;
        let d = (c1 * c2) % &ek.nn;
        RawCiphertext(Cow::Owned(d))
    }
}

impl<'c, 'm, 'd> Add<EncryptionKey, RawPlaintext<'m>, RawCiphertext<'c>, RawCiphertext<'d>>
for OptimizedPaillier
{
    fn add(ek: &EncryptionKey, m: RawPlaintext<'m>, c: RawCiphertext<'c>) -> RawCiphertext<'d> {
        let c1 = (m.0.borrow() as &BigInt * &ek.n + 1) % &ek.nn;
        let c2 = c.0.borrow() as &BigInt;
        let d = (c1 * c2) % &ek.nn;
        RawCiphertext(Cow::Owned(d))
    }
}

impl<'c, 'm, 'd> Mul<EncryptionKey, RawCiphertext<'c>, RawPlaintext<'m>, RawCiphertext<'d>>
for OptimizedPaillier
{
    fn mul(ek: &EncryptionKey, c: RawCiphertext<'c>, m: RawPlaintext<'m>) -> RawCiphertext<'d> {
        RawCiphertext(Cow::Owned(BigInt::mod_pow(
            c.0.borrow(),
            m.0.borrow(),
            &ek.nn,
        )))
    }
}

impl<'c, 'm, 'd> Mul<EncryptionKey, RawPlaintext<'m>, RawCiphertext<'c>, RawCiphertext<'d>>
for OptimizedPaillier
{
    fn mul(ek: &EncryptionKey, m: RawPlaintext<'m>, c: RawCiphertext<'c>) -> RawCiphertext<'d> {
        RawCiphertext(Cow::Owned(BigInt::mod_pow(
            c.0.borrow(),
            m.0.borrow(),
            &ek.nn,
        )))
    }
}

impl Clone for EncryptionKey {
    fn clone(&self) -> Self {
        EncryptionKey {
            alpha_size: self.alpha_size.clone(),
            n: self.n.clone(),
            nn: self.nn.clone(),
            h: self.h.clone(),
            hn: self.hn.clone(),
        }
    }
}

impl EncryptionKey {
    pub fn new(alpha_size: usize, n: BigInt, h: BigInt, hn: BigInt) -> Self {
        EncryptionKey {
            alpha_size,
            n: n.clone(),
            nn: n.clone() * n.clone(),
            h: h.clone(),
            hn: hn.clone(),
        }
    }

    /// Generate an encryption key from modulus n and alpha size
    pub fn from_n(n: BigInt, alpha_size: usize) -> Self {
        let nn = &n * &n;
        
        // Find suitable y that is coprime with n
        let y;
        loop {
            let random = BigInt::sample_below(&n);
            if random.gcd(&n) == BigInt::one() {
                y = random;
                break;
            }
        }
        // Calculate beta = phi(n)/(4*alpha) where phi(n) = (p-1)(q-1)
        // Since we don't know p and q, we use y to generate h

        let h = BigInt::mod_pow(&y, &BigInt::from(2u64), &n);
        let h_clone = h.clone();  // Clone h before moving it
        
        EncryptionKey {
            alpha_size,
            n: n.clone(),
            nn: nn.clone(),
            h,
            hn: BigInt::mod_pow(&h_clone, &n, &nn),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_encryption_key_generation() {
        // Create test primes for n
        let p = BigInt::from(11u64);
        let q = BigInt::from(13u64);
        let n = &p * &q;
        
        let ek = EncryptionKey::from_n(n.clone(), 8);
        
        // Basic validation
        assert_eq!(ek.n, n);
        assert_eq!(ek.nn, &n * &n);
        assert_eq!(ek.alpha_size, 8);
        
        // Verify h is in the correct range
        assert!(ek.h < n);
        assert!(ek.h > BigInt::zero());
        
        // Verify hn is correctly computed
        assert_eq!(ek.hn, BigInt::mod_pow(&ek.h, &n, &ek.nn));
    }
}
