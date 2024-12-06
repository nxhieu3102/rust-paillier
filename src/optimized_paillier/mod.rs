pub mod keygen;
pub mod traits;
pub mod encoding;
pub mod core;

use std::borrow::Cow;

pub use traits::*;
pub use encoding::*;
pub use crate::optimized_paillier::core::*;

use crate::BigInt;

/// Main struct onto which most operations are added.
pub struct OptimizedPaillier;
// values to compute public and secret key
pub struct NGen {
    pub alpha_size: usize, // bit size of alpha, generate random for encryption
    pub n: BigInt, // n = p * q
    pub p: BigInt, // first prime
    pub q: BigInt, // second prime
    pub div_p: BigInt, // div_p | (p - 1)
    pub div_q: BigInt, // div_q | (q - 1)
}

// public key
pub struct EncryptionKey {
    pub alpha_size: usize, // bit size of alpha
    pub n: BigInt, // n = p * q
    pub nn: BigInt, // n = n * n
    pub h: BigInt, // generator h = -y^(2*beta) mod n
    pub hn: BigInt, // pre-compute h^n mod n^2
}

// secret key
pub struct DecryptionKey {
    pub p: BigInt, // prime, for fast decryption (CRT)
    pub q: BigInt, // prime, for fast decryption (CRT)
    pub alpha: BigInt, // alpha = div_p * div_q
    pub n: BigInt, // n = p * q
    pub nn: BigInt, // nn = n * n
}

/// Unencrypted message without type information.
///
/// Used mostly for internal purposes and advanced use-cases.
#[derive(Clone, Debug, PartialEq)]
pub struct RawPlaintext<'b>(pub Cow<'b, BigInt>);

/// Encrypted message without type information.
///
/// Used mostly for internal purposes and advanced use-cases.
#[derive(Clone, Debug, PartialEq)]
pub struct RawCiphertext<'b>(pub Cow<'b, BigInt>);