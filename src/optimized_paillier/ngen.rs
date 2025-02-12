use curv::arithmetic::{Integer, Modulo, One, Samplable};
use curv::BigInt;
use crate::optimized_paillier::{DecryptionKey, EncryptionKey, NGen};

impl NGen {
    /// Generate default encryption and decryption keys from NGen
    pub fn keys(&self) -> (EncryptionKey, DecryptionKey) {
        let nn: BigInt = &self.n * &self.n;

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
                p: self.p.clone(),
                q: self.q.clone(),
            },
        )
    }
}
