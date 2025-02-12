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

impl OptimizedPaillier {
    pub fn find_divisors(p: &BigInt, q: &BigInt, alpha_bit_length: usize) -> Option<(BigInt, BigInt, BigInt, BigInt)> {
        // p = 2 * div_p * other_div_p + 1
        // q = 2 * div_q * other_div_q + 1
        
        // Calculate p-1 and q-1, then divide by 2
        let p_half = (p - 1u64) / 2u64;
        let q_half = (q - 1u64) / 2u64;

        // Try to factor p_half and q_half
        if let (Some((div_p, other_div_p)), Some((div_q, other_div_q))) = 
            (Self::factor_with_size(&p_half, alpha_bit_length/2), 
             Self::factor_with_size(&q_half, alpha_bit_length/2)) {
            
            // Verify all conditions
            if are_all_primes(&[&div_p, &div_q]) 
                && check_coprime(&[&div_p, &div_q, &other_div_p, &other_div_q]) {
                
                // Verify the reconstruction
                let p_check = BigInt::from(2u64) * &div_p * &other_div_p + 1u64;
                let q_check = BigInt::from(2u64) * &div_q * &other_div_q + 1u64;
                
                if p_check == *p && q_check == *q {
                    return Some((div_p, other_div_p, div_q, other_div_q));
                }
            }
        }
        None
    }

    fn factor_with_size(n: &BigInt, target_size: usize) -> Option<(BigInt, BigInt)> {
        let min_prime = BigInt::from(2u64).pow((target_size as u32) - 1);
        let max_prime = BigInt::from(2u64).pow(target_size as u32);

        let mut potential_div = min_prime.clone();
        while &potential_div < &max_prime {
            if n % &potential_div == BigInt::zero() {
                let other_div = n / &potential_div;
                if &potential_div * &other_div == *n {
                    return Some((potential_div, other_div));
                }
            }
            potential_div += 1u64;
        }
        None
    }

    pub fn verify_ngen(ngen: &NGen) -> bool {
        // Verify that p and q are constructed correctly
        let other_div_p = ngen.other_div_p();  // Call the method
        let other_div_q = ngen.other_div_q();  // Call the method
        
        let p_check = BigInt::from(2u64) * &ngen.div_p * &other_div_p + 1u64;
        let q_check = BigInt::from(2u64) * &ngen.div_q * &other_div_q + 1u64;

        // Check all conditions
        p_check == ngen.p 
            && q_check == ngen.q
            && are_all_primes(&[&ngen.p, &ngen.q])
            && are_all_primes(&[&ngen.div_p, &ngen.div_q])
            && check_coprime(&[&ngen.div_p, &ngen.div_q, &other_div_p, &other_div_q])
    }
}

// You'll need to add this field to NGen struct if not already present
impl NGen {
    pub fn other_div_p(&self) -> BigInt {
        ((&self.p - 1u64) / 2u64) / &self.div_p
    }

    pub fn other_div_q(&self) -> BigInt {
        ((&self.q - 1u64) / 2u64) / &self.div_q
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_divisors() {
        // Create known primes with the structure we expect
        let div_p = BigInt::from(11u64);  // small prime
        let div_q = BigInt::from(13u64);  // small prime
        let other_div_p = BigInt::from(17u64);
        let other_div_q = BigInt::from(19u64);

        // Construct p and q: p = 2 * div_p * other_div_p + 1
        let p = BigInt::from(2u64) * &div_p * &other_div_p + 1u64;
        let q = BigInt::from(2u64) * &div_q * &other_div_q + 1u64;

        // Test find_divisors
        let result = OptimizedPaillier::find_divisors(&p, &q, 8);
        assert!(result.is_some());
        
        let (found_div_p, found_other_div_p, found_div_q, found_other_div_q) = result.unwrap();
        assert_eq!(found_div_p, div_p);
        assert_eq!(found_other_div_p, other_div_p);
        assert_eq!(found_div_q, div_q);
        assert_eq!(found_other_div_q, other_div_q);
    }

    #[test]
    fn test_verify_ngen() {
        // Create a valid NGen structure
        let div_p = BigInt::from(11u64);
        let div_q = BigInt::from(13u64);
        let other_div_p = BigInt::from(17u64);
        let other_div_q = BigInt::from(19u64);

        let p = BigInt::from(2u64) * &div_p * &other_div_p + 1u64;
        let q = BigInt::from(2u64) * &div_q * &other_div_q + 1u64;
        
        let ngen = NGen {
            n: &p * &q,
            p: p,
            q: q,
            div_p: div_p,
            div_q: div_q,
            alpha_size: 8,
        };

        assert!(OptimizedPaillier::verify_ngen(&ngen));
    }

    #[test]
    fn test_factor_with_size() {
        // Create a number that we know can be factored
        let factor1 = BigInt::from(11u64);  // 4 bits
        let factor2 = BigInt::from(13u64);  // 4 bits
        let n = &factor1 * &factor2;

        let result = OptimizedPaillier::factor_with_size(&n, 4);
        assert!(result.is_some());
        
        let (found1, found2) = result.unwrap();
        assert!(
            (found1 == factor1 && found2 == factor2) ||
            (found1 == factor2 && found2 == factor1)
        );
    }

    #[test]
    fn test_ngen_methods() {
        let div_p = BigInt::from(11u64);
        let div_q = BigInt::from(13u64);
        let other_div_p = BigInt::from(17u64);
        let other_div_q = BigInt::from(19u64);

        let p = BigInt::from(2u64) * &div_p * &other_div_p + 1u64;
        let q = BigInt::from(2u64) * &div_q * &other_div_q + 1u64;
        
        let ngen = NGen {
            n: &p * &q,
            p: p,
            q: q,
            div_p: div_p,
            div_q: div_q,
            alpha_size: 8,
        };

        assert_eq!(ngen.other_div_p(), other_div_p);
        assert_eq!(ngen.other_div_q(), other_div_q);
    }
}
