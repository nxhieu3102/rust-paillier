use std::borrow::Cow;
use curv::arithmetic::Samplable;
use curv::BigInt;
use crate::optimized_paillier::{EncryptionKey, RawCiphertext, RawPlaintext};

#[derive(Debug, PartialEq)]
pub struct Randomness(pub BigInt);

impl Randomness {
    pub fn sample(ek: &EncryptionKey) -> Randomness {
        Randomness(BigInt::sample(ek.alpha_size))
    }
}

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
