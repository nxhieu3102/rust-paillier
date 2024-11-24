use curv::arithmetic::*;

use super::*;

impl NGen {
    /// Generate default encryption and decryption keys from NGen
    pub fn keys(&self) -> (EncryptionKey, DecryptionKey) {
       todo!()
    }
}

// --------------------------
#[derive(Debug, PartialEq)]
pub struct Randomness(pub BigInt);

#[derive(Debug, PartialEq)]
pub struct PrecomputedRandomness(BigInt);

impl Randomness {
    pub fn sample(ek: &EncryptionKey) -> Randomness {
        Randomness(BigInt::sample_below(&ek.n))
    }
}

impl<'ek, 'r> PrecomputeRandomness<&'ek EncryptionKey, &'r BigInt, PrecomputedRandomness>
    for OptimizedPaillier
{
    fn precompute(ek: &'ek EncryptionKey, r: &'r BigInt) -> PrecomputedRandomness {
        todo!()
    }
}

// --------------------------
// internal functions, will be used in encoding/integral
// execute on raw plaintext and raw ciphertext

impl<'m, 'd> Encrypt<EncryptionKey, RawPlaintext<'m>, RawCiphertext<'d>> for OptimizedPaillier {
    fn encrypt(ek: &EncryptionKey, m: RawPlaintext<'m>) -> RawCiphertext<'d> {
        todo!()
    }
}

impl<'c, 'd> Rerandomize<EncryptionKey, RawCiphertext<'c>, RawCiphertext<'d>> for OptimizedPaillier {
    fn rerandomize(ek: &EncryptionKey, c: RawCiphertext<'c>) -> RawCiphertext<'d> {
        todo!()
    }
}

impl<'c, 'm> Decrypt<DecryptionKey, RawCiphertext<'c>, RawPlaintext<'m>> for OptimizedPaillier {
    fn decrypt(dk: &DecryptionKey, c: RawCiphertext<'c>) -> RawPlaintext<'m> {
        todo!()
    }
}

impl<'c, 'm> Open<DecryptionKey, RawCiphertext<'c>, RawPlaintext<'m>, Randomness> for OptimizedPaillier {
    fn open(dk: &DecryptionKey, c: RawCiphertext<'c>) -> (RawPlaintext<'m>, Randomness) {
        todo!()
    }
}

// Add and mul functions on raw plaintext and ciphertext

impl<'c1, 'c2, 'd> Add<EncryptionKey, RawCiphertext<'c1>, RawCiphertext<'c2>, RawCiphertext<'d>>
    for OptimizedPaillier
{
    fn add(
        ek: &EncryptionKey,
        c1: RawCiphertext<'c1>,
        c2: RawCiphertext<'c2>,
    ) -> RawCiphertext<'d> {
        todo!()
    }
}

impl<'c, 'm, 'd> Add<EncryptionKey, RawCiphertext<'c>, RawPlaintext<'m>, RawCiphertext<'d>>
    for OptimizedPaillier
{
    fn add(ek: &EncryptionKey, c: RawCiphertext<'c>, m: RawPlaintext<'m>) -> RawCiphertext<'d> {
        todo!()
    }
}

impl<'c, 'm, 'd> Add<EncryptionKey, RawPlaintext<'m>, RawCiphertext<'c>, RawCiphertext<'d>>
    for OptimizedPaillier
{
    fn add(ek: &EncryptionKey, m: RawPlaintext<'m>, c: RawCiphertext<'c>) -> RawCiphertext<'d> {
        todo!()
    }
}

impl<'c, 'm, 'd> Mul<EncryptionKey, RawCiphertext<'c>, RawPlaintext<'m>, RawCiphertext<'d>>
    for OptimizedPaillier
{
    fn mul(ek: &EncryptionKey, c: RawCiphertext<'c>, m: RawPlaintext<'m>) -> RawCiphertext<'d> {
        todo!()
    }
}

impl<'c, 'm, 'd> Mul<EncryptionKey, RawPlaintext<'m>, RawCiphertext<'c>, RawCiphertext<'d>>
    for OptimizedPaillier
{
    fn mul(ek: &EncryptionKey, m: RawPlaintext<'m>, c: RawCiphertext<'c>) -> RawCiphertext<'d> {
        todo!()
    }
}


#[cfg(test)]
mod tests {

    use crate::optimized_paillier::NGen;
    use super::*;

    extern crate serde_json;

    fn text_ngen() -> NGen {
        todo!()
    }

    #[test]
    fn test_encryption_decryption() {
        todo!()
    }

    #[test]
    fn test_opening() {
        todo!()
    }

    #[test]
    fn test_add_ciphertext() {
        todo!()
    }

    #[test]
    fn test_add_plaintext() {
        todo!()
    }

    #[test]
    fn test_mul_plaintext() {
        todo!()
    }

    #[test]
    fn test_key_serialization() {
        todo!()
    }

    #[test]
    fn test_failing_deserialize() {
        todo!()
    }
}