pub mod keygen;
pub mod traits;
pub mod encoding;
pub mod serialize;
mod encryption_key;
mod decryption_key;
mod precomputeTable;
mod utils;
mod ngen;
mod test;
mod primesample;

use std::borrow::Cow;
use curv::BigInt;
use serde::Serialize;
pub use traits::*;
pub use encoding::*;
pub use crate::optimized_paillier::serialize::*;


/// Main struct onto which most operations are added.
pub struct OptimizedPaillier;
// values to compute public and secret key
#[derive(Clone)]
pub struct NGen {
    pub alpha_size: usize, // bit size of alpha, generate random for encryption
    pub n: BigInt, // n = p * q
    pub p: BigInt, // first prime
    pub q: BigInt, // second prime
    pub div_p: BigInt, // div_p | (p - 1)
    pub div_q: BigInt, // div_q | (q - 1)
}

// public key
#[derive(Serialize)]

pub struct EncryptionKey {
    pub alpha_size: usize, // bit size of alpha
    pub n: BigInt, // n = p * q
    pub nn: BigInt, // n = n * n
    pub h: BigInt, // generator h = -y^(2*beta) mod n
    pub hn: BigInt, // pre-compute h^n mod n^2
}

// secret key
#[derive(Serialize)]

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

pub struct PrecomputeTable {
    pow_size: usize,
    block_size: usize,
    modulo: BigInt,
    table: Vec<Vec<BigInt>>,
}