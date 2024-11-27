// support plaintext/ciphertext in u64
use std::{borrow::Borrow, marker::PhantomData};

use std::convert::TryFrom;

use super::EncodedCiphertext;
use crate::optimized_paillier::*;

// encrypt plaintext in u64 --> ciphertext in u64
impl<EK> Encrypt<EK, u64, EncodedCiphertext<u64>> for OptimizedPaillier
where
    for<'p, 'c> Self: Encrypt<EK, RawPlaintext<'p>, RawCiphertext<'c>>,
{
    fn encrypt(ek: &EK, m: u64) -> EncodedCiphertext<u64> {
        let c = Self::encrypt(ek, RawPlaintext::from(BigInt::from(m)));
        EncodedCiphertext {
            raw: c.into(),
            components: 1,
            _phantom: PhantomData,
        }
    }
}

// decrypt cipher text in u64 --> plaintext in u64
impl<DK, C> Decrypt<DK, C, u64> for OptimizedPaillier
where
    for<'c, 'p> Self: Decrypt<DK, RawCiphertext<'c>, RawPlaintext<'p>>,
    C: Borrow<EncodedCiphertext<u64>>,
{
    fn decrypt(dk: &DK, c: C) -> u64 {
        let m = Self::decrypt(dk, RawCiphertext::from(&c.borrow().raw));
        u64::try_from(&BigInt::from(m)).unwrap()
    }
}

// ciphertext1 + ciphertext2 --> ciphertext3 (in u64)
impl<EK, C1, C2> Add<EK, C1, C2, EncodedCiphertext<u64>> for OptimizedPaillier
where
    for<'c1, 'c2, 'd> Self: Add<EK, RawCiphertext<'c1>, RawCiphertext<'c2>, RawCiphertext<'d>>,
    C1: Borrow<EncodedCiphertext<u64>>,
    C2: Borrow<EncodedCiphertext<u64>>,
{
    fn add(ek: &EK, c1: C1, c2: C2) -> EncodedCiphertext<u64> {
        let d = Self::add(
            ek,
            RawCiphertext::from(&c1.borrow().raw),
            RawCiphertext::from(&c2.borrow().raw),
        );
        EncodedCiphertext {
            raw: d.into(),
            components: 1,
            _phantom: PhantomData,
        }
    }
}

// ciphertext1 + plaintext --> ciphertext2 (in u64)
impl<EK, C> Add<EK, C, u64, EncodedCiphertext<u64>> for OptimizedPaillier
where
    for<'c, 'p, 'd> Self: Add<EK, RawCiphertext<'c>, RawPlaintext<'p>, RawCiphertext<'d>>,
    C: Borrow<EncodedCiphertext<u64>>,
{
    fn add(ek: &EK, c: C, p: u64) -> EncodedCiphertext<u64> {
        let d = Self::add(
            ek,
            RawCiphertext::from(&c.borrow().raw),
            RawPlaintext::from(BigInt::from(p)),
        );
        EncodedCiphertext {
            raw: d.into(),
            components: 1,
            _phantom: PhantomData,
        }
    }
}

// plaintext + ciphertext1 --> ciphertext2 (in u64)
impl<EK, C2> Add<EK, u64, C2, EncodedCiphertext<u64>> for OptimizedPaillier
where
    for<'m, 'c, 'd> Self: Add<EK, RawPlaintext<'m>, RawCiphertext<'c>, RawCiphertext<'d>>,
    C2: Borrow<EncodedCiphertext<u64>>,
{
    fn add(ek: &EK, m1: u64, c2: C2) -> EncodedCiphertext<u64> {
        let d = Self::add(
            ek,
            RawPlaintext::from(BigInt::from(m1)),
            RawCiphertext::from(&c2.borrow().raw),
        );
        EncodedCiphertext {
            raw: d.into(),
            components: 1,
            _phantom: PhantomData,
        }
    }
}

// ciphertext1 * plaintext --> ciphertext2 (in u64)
impl<EK, C> Mul<EK, C, u64, EncodedCiphertext<u64>> for OptimizedPaillier
where
    for<'c, 'm, 'd> Self: Mul<EK, RawCiphertext<'c>, RawPlaintext<'m>, RawCiphertext<'d>>,
    C: Borrow<EncodedCiphertext<u64>>,
{
    fn mul(ek: &EK, c: C, m: u64) -> EncodedCiphertext<u64> {
        let d = Self::mul(
            ek,
            RawCiphertext::from(&c.borrow().raw),
            RawPlaintext::from(BigInt::from(m)),
        );
        EncodedCiphertext {
            raw: d.into(),
            components: 1,
            _phantom: PhantomData,
        }
    }
}

// plaintext * ciphertext1 --> ciphertext2 (in u64)
impl<EK, C> Mul<EK, u64, C, EncodedCiphertext<u64>> for OptimizedPaillier
where
    for<'m, 'c, 'd> Self: Mul<EK, RawPlaintext<'m>, RawCiphertext<'c>, RawCiphertext<'d>>,
    C: Borrow<EncodedCiphertext<u64>>,
{
    fn mul(ek: &EK, m: u64, c: C) -> EncodedCiphertext<u64> {
        let d = Self::mul(
            ek,
            RawPlaintext::from(BigInt::from(m)),
            RawCiphertext::from(&c.borrow().raw),
        );
        EncodedCiphertext {
            raw: d.into(),
            components: 1,
            _phantom: PhantomData,
        }
    }
}

#[cfg(test)]
mod tests {
    use curv::arithmetic::traits::*;

    use super::*;
    use crate::optimized_paillier::NGen;

    // create sample NGen for test
    fn test_ngen() -> NGen {
        todo!()
    }

    #[test]
    fn test_encrypt_decrypt() {
        todo!()
    }

    #[test]
    fn test_add_plaintext() {
        todo!()
    }

    #[test]
    fn test_add_ciphertext() {
        todo!()
    }

    #[test]
    fn test_mul_plaintext() {
        todo!()
    }
}
