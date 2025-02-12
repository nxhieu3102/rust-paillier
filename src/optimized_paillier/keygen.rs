use curv::arithmetic::Samplable;
use curv::arithmetic::traits::*;
use crate::optimized_paillier::traits::KeyGeneration;

use super::{NGen, OptimizedPaillier};
use curv::BigInt;
use serde::Serialize; // To enable serialization for structs
use serde_json::{self, Value, Map};
use crate::optimized_paillier::primesample::{are_all_primes, check_coprime, PrimeSampable};


impl KeyGeneration<NGen> for OptimizedPaillier {
    fn ngen_with_modulus_size(mut n_bit_length: usize, mut alpha_bit_length: usize) -> NGen {
        loop {
            let div_p = BigInt::sample_prime(alpha_bit_length / 2);
            let div_q = BigInt::sample_prime(alpha_bit_length / 2);
            let other_bit_length = (n_bit_length - alpha_bit_length) / 2 - 1;
            let mut other_div_p = BigInt::sample(other_bit_length);
            let mut other_div_q = BigInt::sample(other_bit_length);

            // We flip the LSB to make sure tue candidate is odd.
            BigInt::set_bit(&mut other_div_p, 0, true);
            BigInt::set_bit(&mut other_div_q, 0, true);

            let p = 2 * &div_p * &other_div_p + 1;
            let q = 2 * &div_q * &other_div_q + 1;

            if are_all_primes(&[&p, &q])
                && check_coprime(&[&div_p, &div_q, &other_div_p, &other_div_q])
            {
                return NGen {
                    n: &p * &q,
                    p,
                    q,
                    div_p,
                    div_q,
                    alpha_size: alpha_bit_length,
                };
            }
        }
    }

    fn ngen_safe_primes_with_modulus_size(n_bit_length: usize, alpha_bit_length: usize) -> NGen {
        // TODO: set max loop
        loop {
            let div_p = BigInt::sample_safe_prime(alpha_bit_length / 2);
            let div_q = BigInt::sample_safe_prime(alpha_bit_length / 2);

            let other_bit_length = (n_bit_length - alpha_bit_length) / 2 - 1;
            let mut other_div_p = BigInt::sample(other_bit_length);
            let mut other_div_q = BigInt::sample(other_bit_length);

            // We flip the LSB to make sure tue candidate is odd.
            BigInt::set_bit(&mut other_div_p, 0, true);
            BigInt::set_bit(&mut other_div_q, 0, true);

            let p = 2 * &div_p * &other_div_p + 1;
            let q = 2 * &div_q * &other_div_q + 1;

            if are_all_primes(&[&p, &q])
                && check_coprime(&[&div_p, &div_q, &other_div_p, &other_div_q])
            {
                return NGen {
                    n: &p * &q,
                    p,
                    q,
                    div_p,
                    div_q,
                    alpha_size: alpha_bit_length,
                };
            }
        }
    }
}
