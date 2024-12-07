//! Abstract operations exposed by the library.

/// Secure generation of NGen
pub trait KeyGeneration<NG> {
    /// Generate fresh NGen with currently recommended security level (2048 bit modulus).
    fn ngen() -> NG {
        Self::ngen_with_modulus_size(2048, 448)
    }
    fn ngen_safe_primes() -> NG {
        Self::ngen_safe_primes_with_modulus_size(2048, 448)
    }
    /// Generate fresh NGen with security level specified as the `bit_length` of the modulus.
    ///
    /// Currently recommended security level is a minimum of 2048 bits.
    fn ngen_with_modulus_size(n_bit_length: usize, alpha_bit_length: usize) -> NG;
    fn ngen_safe_primes_with_modulus_size(n_bit_length: usize, alpha_bit_length: usize) -> NG;
}

// pub trait PrecomputeRandomness<EK, R, PR> {
//     fn precompute(ek: EK, r: R) -> PR;
// }

pub trait PowWithPrecomputeTable<PT, BI, US> {
    fn calculate_precompute_table(g: BI, block_size: US, pow_size: US, modulo: BI) -> PT;
    fn calculate_precompute_table_with_dp(g: BI, block_size: US, pow_size: US, modulo: BI) -> PT;
    fn convert_into_block(precompute_table: &PT, x: &BI) -> Vec<US>;
    fn pow(precompute_table: &PT, pow: &BI) -> BI;
}

/// Encryption of plaintext.
pub trait Encrypt<EK, PT, CT> {
    /// Encrypt plaintext `m` under key `ek` into a ciphertext.
    fn encrypt(ek: &EK, m: PT) -> CT;
}

pub trait EncryptWithPrecomputeTable<EK, PT, CT, PC> {
    /// Encrypt plaintext `m` under key `ek` into a ciphertext.
    fn encrypt_with_precompute_table(precompute_table: &PC, ek: &EK, m: PT) -> CT;
}

// pub trait EncryptWithChosenRandomness<EK, PT, R, CT> {
//     fn encrypt_with_chosen_randomness(ek: &EK, m: PT, r: R) -> CT;
// }

/// Decryption of ciphertext.
pub trait Decrypt<DK, CT, PT> {
    /// Decrypt ciphertext `c` using key `dk` into a plaintext.
    fn decrypt(ek: &DK, c: CT) -> PT;
}

/// Decryption of ciphertext use Chinese Remainder Theorem (CRT)
pub trait DecryptCRT<DK, CT, PT> {
    /// Decrypt ciphertext `c` using key `dk` into a plaintext.
    fn decrypt_crt(dk: &DK, c: CT) -> PT;
}

// /// Opening of ciphertext.
// ///
// /// Unlike decryption this also returns the randomness used.
// pub trait Open<DK, CT, PT, R> {
//     /// Open ciphertext `c` using key `dk` into a plaintext and a randomness.
//     fn open(dk: &DK, c: CT) -> (PT, R);
// }

/// Addition of two ciphertexts.
pub trait Add<EK, CT1, CT2, CT> {
    /// Homomorphically combine ciphertexts `c1` and `c2` to obtain a ciphertext containing
    /// the sum of the two underlying plaintexts, reduced modulus `n` from `ek`.
    fn add(ek: &EK, c1: CT1, c2: CT2) -> CT;
}

/// Multiplication of ciphertext with plaintext.
pub trait Mul<EK, CT1, PT2, CT> {
    /// Homomorphically combine ciphertext `c1` and plaintext `m2` to obtain a ciphertext
    /// containing the multiplication of the (underlying) plaintexts, reduced modulus `n` from `ek`.
    fn mul(ek: &EK, c1: CT1, m2: PT2) -> CT;
}

// /// Rerandomisation of ciphertext.
// pub trait Rerandomize<EK, CT1, CT> {
//     /// Rerandomise ciphertext `c` to hide any history of which homomorphic operations were
//     /// used to compute it, making it look exactly like a fresh encryption of the same plaintext.
//     fn rerandomize(ek: &EK, c: CT1) -> CT;
// }
