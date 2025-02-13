// support plaintext/ciphertext in u64
use std::{borrow::Borrow, marker::PhantomData, u128, u64};

use std::convert::TryFrom;

use super::EncodedCiphertext;
use crate::optimized_paillier::*;

// encrypt plaintext in u64 --> ciphertext in u64
impl<EK> Encrypt<EK, u64, EncodedCiphertext<u64>> for OptimizedPaillier
where
    for<'p, 'c> Self: Encrypt<EK, RawPlaintext<'p>, RawCiphertext<'c>>,
{
    fn encrypt(ek: &EK, m: u64) -> EncodedCiphertext<u64> {
        let c: RawCiphertext<'_> = Self::encrypt(ek, RawPlaintext::from(BigInt::from(m)));
        EncodedCiphertext {
            raw: c.into(),
            components: 1,
            _phantom: PhantomData,
        }
    }
}

// faster encrypt plaintext in u64 --> ciphertext in u64
impl<EK> EncryptWithPrecomputeTable<EK, u64, EncodedCiphertext<u64>, PrecomputeTable>
    for OptimizedPaillier
where
    for<'p, 'c> Self:
        EncryptWithPrecomputeTable<EK, RawPlaintext<'p>, RawCiphertext<'c>, PrecomputeTable>,
{
    fn encrypt_with_precompute_table(
        precompute_table: &PrecomputeTable,
        ek: &EK,
        m: u64,
    ) -> EncodedCiphertext<u64> {
        let c = Self::encrypt_with_precompute_table(
            precompute_table,
            ek,
            RawPlaintext::from(BigInt::from(m)),
        );

        EncodedCiphertext {
            raw: c.into(),
            components: 1,
            _phantom: PhantomData,
        }
    }
}

// decrypt cipher text in u64 --> plaintext in u64
impl<DK, C> Decrypt<DK, C, u64> for OptimizedPaillier
where
    for<'c, 'p> Self: Decrypt<DK, RawCiphertext<'c>, RawPlaintext<'p>>,
    C: Borrow<EncodedCiphertext<u64>>,
{
    fn decrypt(dk: &DK, c: C) -> u64 {
        let m = Self::decrypt(dk, RawCiphertext::from(&c.borrow().raw));
        let bigint = BigInt::from(m);
        if (bigint > BigInt::from(u64::MAX)) {
            return u64::MAX;
        }
        u64::try_from(&bigint).unwrap()
    }
}

// faster decrypt cipher text in u64 --> plaintext in u64
impl<DK, C> DecryptCRT<DK, C, u64> for OptimizedPaillier
where
    for<'c, 'p> Self: DecryptCRT<DK, RawCiphertext<'c>, RawPlaintext<'p>>,
    C: Borrow<EncodedCiphertext<u64>>,
{
    fn decrypt_crt(dk: &DK, c: C) -> u64 {
        let m = Self::decrypt_crt(dk, RawCiphertext::from(&c.borrow().raw));
        u64::try_from(&BigInt::from(m)).unwrap()
    }
}

// ciphertext1 + ciphertext2 --> ciphertext3 (in u64)
impl<EK, C1, C2> Add<EK, C1, C2, EncodedCiphertext<u64>> for OptimizedPaillier
where
    for<'c1, 'c2, 'd> Self: Add<EK, RawCiphertext<'c1>, RawCiphertext<'c2>, RawCiphertext<'d>>,
    C1: Borrow<EncodedCiphertext<u64>>,
    C2: Borrow<EncodedCiphertext<u64>>,
{
    fn add(ek: &EK, c1: C1, c2: C2) -> EncodedCiphertext<u64> {
        let d = Self::add(
            ek,
            RawCiphertext::from(&c1.borrow().raw),
            RawCiphertext::from(&c2.borrow().raw),
        );
        EncodedCiphertext {
            raw: d.into(),
            components: 1,
            _phantom: PhantomData,
        }
    }
}

// ciphertext1 + plaintext --> ciphertext2 (in u64)
impl<EK, C> Add<EK, C, u64, EncodedCiphertext<u64>> for OptimizedPaillier
where
    for<'c, 'p, 'd> Self: Add<EK, RawCiphertext<'c>, RawPlaintext<'p>, RawCiphertext<'d>>,
    C: Borrow<EncodedCiphertext<u64>>,
{
    fn add(ek: &EK, c: C, p: u64) -> EncodedCiphertext<u64> {
        let d = Self::add(
            ek,
            RawCiphertext::from(&c.borrow().raw),
            RawPlaintext::from(BigInt::from(p)),
        );
        EncodedCiphertext {
            raw: d.into(),
            components: 1,
            _phantom: PhantomData,
        }
    }
}

// plaintext + ciphertext1 --> ciphertext2 (in u64)
impl<EK, C2> Add<EK, u64, C2, EncodedCiphertext<u64>> for OptimizedPaillier
where
    for<'m, 'c, 'd> Self: Add<EK, RawPlaintext<'m>, RawCiphertext<'c>, RawCiphertext<'d>>,
    C2: Borrow<EncodedCiphertext<u64>>,
{
    fn add(ek: &EK, m1: u64, c2: C2) -> EncodedCiphertext<u64> {
        let d = Self::add(
            ek,
            RawPlaintext::from(BigInt::from(m1)),
            RawCiphertext::from(&c2.borrow().raw),
        );
        EncodedCiphertext {
            raw: d.into(),
            components: 1,
            _phantom: PhantomData,
        }
    }
}

// ciphertext1 * plaintext --> ciphertext2 (in u64)
impl<EK, C> Mul<EK, C, u64, EncodedCiphertext<u64>> for OptimizedPaillier
where
    for<'c, 'm, 'd> Self: Mul<EK, RawCiphertext<'c>, RawPlaintext<'m>, RawCiphertext<'d>>,
    C: Borrow<EncodedCiphertext<u64>>,
{
    fn mul(ek: &EK, c: C, m: u64) -> EncodedCiphertext<u64> {
        let d = Self::mul(
            ek,
            RawCiphertext::from(&c.borrow().raw),
            RawPlaintext::from(BigInt::from(m)),
        );
        EncodedCiphertext {
            raw: d.into(),
            components: 1,
            _phantom: PhantomData,
        }
    }
}

// plaintext * ciphertext1 --> ciphertext2 (in u64)
impl<EK, C> Mul<EK, u64, C, EncodedCiphertext<u64>> for OptimizedPaillier
where
    for<'m, 'c, 'd> Self: Mul<EK, RawPlaintext<'m>, RawCiphertext<'c>, RawCiphertext<'d>>,
    C: Borrow<EncodedCiphertext<u64>>,
{
    fn mul(ek: &EK, m: u64, c: C) -> EncodedCiphertext<u64> {
        let d = Self::mul(
            ek,
            RawPlaintext::from(BigInt::from(m)),
            RawCiphertext::from(&c.borrow().raw),
        );
        EncodedCiphertext {
            raw: d.into(),
            components: 1,
            _phantom: PhantomData,
        }
    }
}

#[cfg(test)]
mod tests {
    use curv::arithmetic::traits::*;

    use super::*;
    use crate::optimized_paillier::NGen;

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
    fn test_encrypt_decrypt() {
        let (ek, dk) = test_ngen().keys();

        let m = 10;
        let c = OptimizedPaillier::encrypt(&ek, m);

        let recovered_m = OptimizedPaillier::decrypt(&dk, &c);
        assert_eq!(recovered_m, m);
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
        let precompute =
            OptimizedPaillier::calculate_precompute_table(base, block_size, pow_size, modulo);

        let m = 10;
        let c = OptimizedPaillier::encrypt_with_precompute_table(&precompute, &ek, m);

        let recovered_m = OptimizedPaillier::decrypt(&dk, c);
        assert_eq!(recovered_m, m);
    }

    #[test]
    fn test_crt_decryption() {
        let (ek, dk) = test_ngen().keys();

        let m = 10;
        let c = OptimizedPaillier::encrypt(&ek, m);

        let recovered_m = OptimizedPaillier::decrypt_crt(&dk, &c);
        assert_eq!(recovered_m, m);
    }

    #[test]
    fn test_add_plaintext() {
        let (ek, dk) = test_ngen().keys();

        let c1 = OptimizedPaillier::encrypt(&ek, 10);
        let m2 = 20;

        let c = OptimizedPaillier::add(&ek, &c1, m2);
        let m = OptimizedPaillier::decrypt(&dk, &c);
        assert_eq!(m, 30);
    }

    #[test]
    fn test_add_ciphertext() {
        let (ek, dk) = test_ngen().keys();

        let c1 = OptimizedPaillier::encrypt(&ek, 10);
        let c2 = OptimizedPaillier::encrypt(&ek, 20);

        let c = OptimizedPaillier::add(&ek, &c1, &c2);
        let m = OptimizedPaillier::decrypt(&dk, &c);
        assert_eq!(m, 30);
    }

    #[test]
    fn test_mul_plaintext() {
        let (ek, dk) = test_ngen().keys();

        let c = OptimizedPaillier::encrypt(&ek, 10);
        let d = OptimizedPaillier::mul(&ek, &c, 20);
        let m = OptimizedPaillier::decrypt(&dk, &d);
        assert_eq!(m, 200);
    }
}
