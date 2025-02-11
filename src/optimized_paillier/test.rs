use curv::BigInt;
use crate::optimized_paillier::PrecomputeTable;

#[cfg(test)]
mod test_pow_with_precompute {
    use crate::optimized_paillier::{OptimizedPaillier, PowWithPrecomputeTable};
    use curv::{arithmetic::Modulo, BigInt};

    use super::PrecomputeTable;

    fn test_pow_with_precompute(precompute: &PrecomputeTable, base: &BigInt, modulo: &BigInt) {
        let pow = BigInt::from(1);
        let result = OptimizedPaillier::pow(precompute, &pow);
        assert_eq!(result, BigInt::mod_pow(base, &pow, modulo));

        let pow = BigInt::from(5);
        let result = OptimizedPaillier::pow(precompute, &pow);
        assert_eq!(result, BigInt::mod_pow(base, &pow, modulo));

        let pow = BigInt::from(20);
        let result = OptimizedPaillier::pow(precompute, &pow);
        assert_eq!(result, BigInt::mod_pow(base, &pow, modulo));

        let pow = BigInt::from(1000);
        let result = OptimizedPaillier::pow(precompute, &pow);
        assert_eq!(result, BigInt::mod_pow(base, &pow, modulo));
    }

    #[test]
    fn precompute() {
        let base = BigInt::from(2);
        let block_size = 3;
        let pow_size = 10;
        let modulo = BigInt::from(1000000000);

        // pow <= 2^10 - 1
        let precompute = OptimizedPaillier::calculate_precompute_table(
            base.clone(),
            block_size,
            pow_size,
            modulo.clone(),
        );

        test_pow_with_precompute(&precompute, &base, &modulo);
    }

    #[test]
    fn precompute_with_dp() {
        let base = BigInt::from(2);
        let block_size = 3;
        let pow_size = 10;
        let modulo = BigInt::from(1000000000);

        // pow <= 2^10 - 1
        let precompute = OptimizedPaillier::calculate_precompute_table_with_dp(
            base.clone(),
            block_size,
            pow_size,
            modulo.clone(),
        );

        test_pow_with_precompute(&precompute, &base, &modulo);
    }
}

#[cfg(test)]
mod tests {
    use curv::arithmetic::{BasicOps, Converter};
    use super::*;
    use crate::optimized_paillier::{Add, Decrypt, DecryptCRT, Encrypt, EncryptWithPrecomputeTable, Mul, NGen, OptimizedPaillier, PowWithPrecomputeTable, RawPlaintext};

    extern crate serde_json;

    // create sample NGen for test
    fn test_ngen() -> NGen {
        let p = BigInt::from_str_radix("58840286422659759040264722526723163115947585338232456760625037250347772947158924579397568010160401824142812407358290596642469990113927112749530655037092283267003056548558029709374658607773847180644927643815153088281601855305598381448858360794678123176275437646277062199420220697194572706984411597767662174219", 10).unwrap();
        let q = BigInt::from_str_radix("64569320288008737248616342555880093394368754507783709070327116553058977898351053473313292166959127254971093796968717357648354685162478156927773865332477516856906959367256797593402514551692581319610393653175392375527614160563282643144940815153885487175996514917461421149259641826709133924683180923570779884947", 10).unwrap();

        let div_p = BigInt::from_str_radix(
            "15020304164245057288431929989769857115735852482951590711910706652979",
            10,
        )
            .unwrap();
        let div_q = BigInt::from_str_radix(
            "21291950558579076623582777617978449486334160877503898213693845753489",
            10,
        )
            .unwrap();

        let n = &p * &q;
        let alpha_size = 448 as usize;

        NGen {
            alpha_size,
            n,
            p,
            q,
            div_p,
            div_q,
        }
    }

    #[test]
    fn test_encryption_decryption() {
        let (ek, dk) = test_ngen().keys();

        let p = RawPlaintext::from(BigInt::from(10));
        let c = OptimizedPaillier::encrypt(&ek, p.clone());

        let recovered_p = OptimizedPaillier::decrypt(&dk, c);
        assert_eq!(recovered_p, p);
    }

    #[test]
    fn test_encryption_with_precompute() {
        let (ek, dk) = test_ngen().keys();

        let base = ek.hn.clone();
        // block_size > 10 --> memory error
        let block_size = 5;
        let pow_size = ek.alpha_size;
        let modulo = ek.nn.clone();

        // pow <= 2^pow_size - 1
        let precompute = OptimizedPaillier::calculate_precompute_table(
            base,
            block_size,
            pow_size,
            modulo,
        );

        let p = RawPlaintext::from(BigInt::from(10));
        let c = OptimizedPaillier::encrypt_with_precompute_table(&precompute, &ek, p.clone());

        let recovered_p = OptimizedPaillier::decrypt(&dk, c);
        assert_eq!(recovered_p, p);
    }

    #[test]
    fn test_crt_decryption() {
        let (ek, dk) = test_ngen().keys();

        let p = RawPlaintext::from(BigInt::from(10));
        let c = OptimizedPaillier::encrypt(&ek, p.clone());

        let recovered_p = OptimizedPaillier::decrypt_crt(&dk, c);
        assert_eq!(recovered_p, p);
    }

    // #[test]
    // fn test_opening() {
    //     todo!()
    // }

    #[test]
    fn test_add_ciphertext() {
        let (ek, dk) = test_ngen().keys();

        let m1 = RawPlaintext::from(BigInt::from(10));
        let c1 = OptimizedPaillier::encrypt(&ek, m1);
        let m2 = RawPlaintext::from(BigInt::from(20));
        let c2 = OptimizedPaillier::encrypt(&ek, m2);

        let c = OptimizedPaillier::add(&ek, c1, c2);
        let m = OptimizedPaillier::decrypt(&dk, c);
        assert_eq!(m, BigInt::from(30).into());
    }

    #[test]
    fn test_add_plaintext() {
        let (ek, dk) = test_ngen().keys();

        let m1 = RawPlaintext::from(BigInt::from(2).pow(120));
        let c1 = OptimizedPaillier::encrypt(&ek, m1);
        let m2 = RawPlaintext::from(BigInt::from(2).pow(120));
        let c = OptimizedPaillier::add(&ek, c1, m2);
        let m = OptimizedPaillier::decrypt(&dk, c);
        assert_eq!(m, BigInt::from(2).pow(121).into());
    }

    #[test]
    fn test_mul_plaintext() {
        let (ek, dk) = test_ngen().keys();

        let m1 = RawPlaintext::from(BigInt::from(10));
        let c1 = OptimizedPaillier::encrypt(&ek, m1);
        let m2 = RawPlaintext::from(BigInt::from(20));

        let c = OptimizedPaillier::mul(&ek, c1, m2);
        let m = OptimizedPaillier::decrypt(&dk, c);
        assert_eq!(m, BigInt::from(200).into());
    }

}

