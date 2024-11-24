use curv::arithmetic::*;
use std::borrow::Borrow;

use super::*;

impl NGen {
    /// Generate default encryption and decryption keys from NGen
    pub fn keys(&self) -> (EncryptionKey, DecryptionKey) {
        let nn = &self.n * &self.n;

        let alpha = &self.div_p * &self.div_q;
        let beta = (&self.p - 1) * (&self.q - 1) / (4 * &self.div_p * &self.div_q);

        let y;
        // TODO: limit loop time
        loop {
            let random = BigInt::sample_below(&self.n);
            if random.gcd(&self.n) == BigInt::one() {
                y = random;
                break;
            }
        }

        // h = -y^(2*beta) (mod N)
        let h = BigInt::mod_pow(&y, &(2 * &beta), &self.n);

        (
            EncryptionKey {
                alpha_size: self.alpha_size.clone(),
                hn: BigInt::mod_pow(&h, &self.n, &nn),
                n: self.n.clone(),
                nn: nn.clone(),
                h,
            },
            DecryptionKey {
                alpha,
                nn,
                n: self.n.clone(),
            },
        )
    }
}

// --------------------------
#[derive(Debug, PartialEq)]
pub struct Randomness(pub BigInt);

impl Randomness {
    pub fn sample(ek: &EncryptionKey) -> Randomness {
        Randomness(BigInt::sample(ek.alpha_size))
    }
}

// --------------------------

impl<'b> From<BigInt> for RawPlaintext<'b> {
    fn from(x: BigInt) -> Self {
        RawPlaintext(Cow::Owned(x))
    }
}

impl<'b> From<&'b BigInt> for RawPlaintext<'b> {
    fn from(x: &'b BigInt) -> Self {
        RawPlaintext(Cow::Borrowed(x))
    }
}

impl<'b> From<RawPlaintext<'b>> for BigInt {
    fn from(x: RawPlaintext<'b>) -> Self {
        x.0.into_owned()
    }
}

impl<'b> From<BigInt> for RawCiphertext<'b> {
    fn from(x: BigInt) -> Self {
        RawCiphertext(Cow::Owned(x))
    }
}

impl<'b> From<&'b BigInt> for RawCiphertext<'b> {
    fn from(x: &'b BigInt) -> Self {
        RawCiphertext(Cow::Borrowed(x))
    }
}

impl<'b> From<RawCiphertext<'b>> for BigInt {
    fn from(x: RawCiphertext<'b>) -> Self {
        x.0.into_owned()
    }
}

// --------------------------
// internal functions, will be used in encoding/integral
// execute on raw plaintext and raw ciphertext

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

impl<'c, 'm> Decrypt<DecryptionKey, RawCiphertext<'c>, RawPlaintext<'m>> for OptimizedPaillier {
    fn decrypt(dk: &DecryptionKey, c: RawCiphertext<'c>) -> RawPlaintext<'m> {
        // l(c^(2*alpha mod n^2), n)
        let dc = BigInt::mod_pow(&c.0, &(2 * &dk.alpha), &dk.nn);
        let lc = (&dc - 1) / &dk.n; // l(u,n) = (u - 1) / n

        // (2* alpha)^(-1) (mod n)
        let inv_alpha = BigInt::mod_inv(&(2 * &dk.alpha), &dk.n).unwrap();

        // m = l(c^(2*alpha mod n^2), n) * (2* alpha)^(-1) (mod n)
        let m = &lc * &inv_alpha % &dk.n;
        RawPlaintext(Cow::Owned(m))
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

#[cfg(test)]
mod tests {

    use super::*;
    use crate::optimized_paillier::NGen;

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
