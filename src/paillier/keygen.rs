//! Key generation following standard recommendations.

use crate::paillier::*;
use crate::{BigInt, PrimeSampable};

impl KeyGeneration<Keypair> for Paillier {
    fn keypair_with_modulus_size(bit_length: usize) -> Keypair {
        let p = BigInt::sample_prime(bit_length / 2);
        let q = BigInt::sample_prime(bit_length / 2);
        Keypair { p, q }
    }

    fn keypair_safe_primes_with_modulus_size(bit_length: usize) -> Keypair {
        let p = BigInt::sample_safe_prime(bit_length / 2);
        let q = BigInt::sample_safe_prime(bit_length / 2);
        Keypair { p, q }
    }
}