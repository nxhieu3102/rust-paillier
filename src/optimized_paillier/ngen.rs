use curv::arithmetic::{Integer, Modulo, One, Samplable};
use curv::BigInt;
use crate::optimized_paillier::{DecryptionKey, EncryptionKey, NGen, OptimizedPaillier};

impl NGen {
    /// Generate default encryption and decryption keys from NGen
    pub fn keys(&self) -> (EncryptionKey, DecryptionKey) {
        let nn: BigInt = &self.n * &self.n;

        let alpha: BigInt = &self.div_p * &self.div_q;
        let beta: BigInt = (&self.p - 1) * (&self.q - 1) / (4 * &self.div_p * &self.div_q);

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
                p: self.p.clone(),
                q: self.q.clone(),
            },
        )
    }

    /// Generate encryption and decryption keys from provided prime numbers
    pub fn keys_with_primes(p: &BigInt, q: &BigInt, alpha_bit_length: usize) -> Option<(EncryptionKey, DecryptionKey)> {
        // Try to find the divisors
        if let Some((div_p, other_div_p, div_q, other_div_q)) = 
            OptimizedPaillier::find_divisors(p, q, alpha_bit_length) {
            
            let n = p * q;
            let nn = &n * &n;
            let alpha = &div_p * &div_q;
            let beta = (p - 1u64) * (q - 1u64) / (BigInt::from(4u64) * &div_p * &div_q);

            // Find suitable y
            let mut y;
            loop {
                let random = BigInt::sample_below(&n);
                if random.gcd(&n) == BigInt::one() {
                    y = random;
                    break;
                }
            }

            // Calculate h = -y^(2*beta) (mod N)
            let h = BigInt::mod_pow(&y, &(2 * &beta), &n);

            let ek = EncryptionKey {
                alpha_size: alpha_bit_length,
                hn: BigInt::mod_pow(&h, &n, &nn),
                n: n.clone(),
                nn: nn.clone(),
                h,
            };

            let dk = DecryptionKey {
                alpha,
                nn,
                n,
                p: p.clone(),
                q: q.clone(),
            };

            Some((ek, dk))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keys_with_primes() {
        // Create known primes with the structure we expect
        let div_p = BigInt::from(11u64);
        let div_q = BigInt::from(13u64);
        let other_div_p = BigInt::from(17u64);
        let other_div_q = BigInt::from(19u64);

        // Construct p and q
        let p = BigInt::from(2u64) * &div_p * &other_div_p + 1u64;
        let q = BigInt::from(2u64) * &div_q * &other_div_q + 1u64;

        // Generate keys
        let keys = NGen::keys_with_primes(&p, &q, 8);
        assert!(keys.is_some());

        let (ek, dk) = keys.unwrap();
        
        // Basic validation
        assert_eq!(dk.p, p);
        assert_eq!(dk.q, q);
        assert_eq!(dk.n, &p * &q);
        assert_eq!(dk.alpha, div_p * div_q);
    }
}
