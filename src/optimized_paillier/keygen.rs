use crate::optimized_paillier::traits::KeyGeneration;

use super::{NGen, OptimizedPaillier};

impl KeyGeneration<NGen> for OptimizedPaillier {
    fn ngen_with_modulus_size(big_length: usize) -> NGen {
        todo!()
    }

    fn ngen_safe_primes_with_modulus_size(big_length: usize) -> NGen {
        todo!()
    }
}