use curv::arithmetic::Samplable;

use crate::optimized_paillier::traits::KeyGeneration;

use super::{NGen, OptimizedPaillier};
use crate::{are_all_primes, check_coprime, BigInt, PrimeSampable};

impl KeyGeneration<NGen> for OptimizedPaillier {
    fn ngen_with_modulus_size(n_bit_length: usize, alpha_bit_length: usize) -> NGen {
        // TODO: set max loop
        let mut count = 0;
        loop {
            println!("{count}");
            count += 1;

            let div_p = BigInt::sample_prime(alpha_bit_length / 2);
            let div_q = BigInt::sample_prime(alpha_bit_length / 2);

            let other_bit_length = (n_bit_length - alpha_bit_length) / 2 - 1;
            let other_div_p = BigInt::sample(other_bit_length);
            let other_div_q = BigInt::sample(other_bit_length);

            let p = 2 * &div_p * &other_div_p + 1;
            let q = 2 * &div_q * &other_div_q + 1;

            println!("{}", are_all_primes(&[&p, &q]));
            println!(
                "{}",
                check_coprime(&[&div_p, &div_q, &other_div_p, &other_div_q])
            );

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
            let other_div_p = BigInt::sample(other_bit_length);
            let other_div_q = BigInt::sample(other_bit_length);

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
