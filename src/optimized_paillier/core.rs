use curv::arithmetic::*;
use rayon::join;
use std::borrow::Borrow;
use std::ops::Div;
use crate::paillier::MinimalEncryptionKey;
use super::*;

impl NGen {
    /// Generate default encryption and decryption keys from NGen
    pub fn keys(&self) -> (EncryptionKey, DecryptionKey) {
        let nn = &self.n * &self.n;

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

// -------------------------- Precompute table to calculate: g^x (g is a constant)
pub struct PrecomputeTable {
    pow_size: usize,
    block_size: usize,
    modulo: BigInt,
    table: Vec<Vec<BigInt>>,
}

impl PrecomputeTable {
    fn calculate_table(
        g: &BigInt,
        block_size: usize,
        pow_size: usize,
        modulo: &BigInt,
    ) -> Vec<Vec<BigInt>> {
        // let i_min = 1 as usize;
        let i_max = pow_size / block_size + if (pow_size % block_size) > 0 { 1 } else { 0 };
        // let j_min = 0 as usize;
        let j_max = (1 << block_size) - 1;

        // table[i][j] = [g^(2^(ib))]^j mod modulo
        let mut table = vec![vec![BigInt::one(); j_max + 1]; i_max + 1];

        for i in 0..=i_max {
            for j in 0..=j_max {
                let tmp1 = BigInt::mod_pow(
                    &BigInt::from(2),
                    &BigInt::from((i * block_size) as u32),
                    &modulo,
                );
                let tmp2 = BigInt::mod_pow(&g, &tmp1, &modulo);
                let tmp3 = BigInt::mod_pow(&tmp2, &BigInt::from(j as u32), &modulo);
                table[i][j] = tmp3;
            }
        }

        table
    }

    fn calculate_table_dp(
        g: &BigInt,
        block_size: usize,
        pow_size: usize,
        modulo: &BigInt,
    ) -> Vec<Vec<BigInt>> {
        // let i_min = 1 as usize;
        let i_max = pow_size / block_size + if (pow_size % block_size) > 0 { 1 } else { 0 };
        // let j_min = 0 as usize;
        let j_max = (1 << block_size) - 1;

        // table[i][j] = [g^(2^(ib))]^j mod modulo
        let mut table = vec![vec![BigInt::one(); j_max + 1]; i_max + 1];

        // base case 0: i = 0, j = 0, table[0][0] = 1

        // base case 1: i = 0, for all j, table[0][j] = [g^(2^(0b))]^j mod modulo = g^j mod modulo
        // table[0][j] = table[0][j - 1] * g mod modulo
        for j in 1..=j_max {
            table[0][j] = BigInt::mod_mul(&table[0][j - 1], &g, &modulo);
        }

        // base case 2: j = 0, for all i, table[i][0] = [g^(2^(ib))]^0 mod modulo = 1
        // already done because by default, all elements in table are 1

        // for all i > 0, table[i][1] = (table[i - 1][1])^(2^b), where b is block_size
        // 2^b as a constant
        let two_pow_b =
            BigInt::mod_pow(&BigInt::from(2), &BigInt::from(block_size as u32), &modulo);

        for i in 1..=i_max {
            table[i][1] = BigInt::mod_pow(&table[i - 1][1], &two_pow_b, &modulo);
        }

        // for i >= 1 and j >= 2: table[i][j] = table[i][j - 1] . table[i][1]
        for i in 1..=i_max {
            for j in 2..=j_max {
                table[i][j] = BigInt::mod_mul(&table[i][j - 1], &table[i][1], &modulo);
            }
        }

        table
    }

    pub fn new(g: BigInt, block_size: usize, pow_size: usize, modulo: BigInt) -> Self {
        let table = Self::calculate_table(&g, block_size, pow_size, &modulo);

        PrecomputeTable {
            table,
            block_size,
            pow_size,
            modulo,
        }
    }

    pub fn new_dp(g: BigInt, block_size: usize, pow_size: usize, modulo: BigInt) -> Self {
        let table = Self::calculate_table_dp(&g, block_size, pow_size, &modulo);

        PrecomputeTable {
            table,
            block_size,
            pow_size,
            modulo,
        }
    }

    fn convert_into_block(&self, x: &BigInt) -> Vec<usize> {
        // convert bigint --> list of bits
        // block_size bits --> group (right to left)
        // each group --> usize/u64/...
        let block_size = self.block_size;
        let pow_size = self.pow_size;
        let num_block = pow_size / block_size + if (pow_size % block_size) > 0 { 1 } else { 0 };

        let mut result = vec![0; num_block];

        for bit_id in 0..pow_size {
            if x.test_bit(bit_id) {
                // bit_id in is the (bit_id % block_size) bit of group (bit_id / block_size)
                // turn on the (bit_id % block_size) bit of group (bit_id / block_size)
                let block_id = bit_id / block_size;
                let bit_id = bit_id % block_size;
                result[block_id] |= 1 << bit_id;
            }
        }

        result
    }

    pub fn compute(&self, pow: &BigInt) -> BigInt {
        let pow_blocks = self.convert_into_block(&pow);
        let mut result = BigInt::one();

        for (id, pow_block) in pow_blocks.iter().enumerate() {
            result = BigInt::mod_mul(&result, &self.table[id][*pow_block], &self.modulo);
        }

        result
    }
}

#[cfg(test)]
mod test_precompute {
    use crate::optimized_paillier::PrecomputeTable;
    use curv::{arithmetic::Modulo, BigInt};

    #[test]
    fn test_pow_with_precompute() {
        let base = BigInt::from(2);
        let modulo = BigInt::from(1000000000);

        // pow <= 2^10 - 1
        let precompute = PrecomputeTable::new(base.clone(), 3, 10, modulo.clone());

        let pow = BigInt::from(1);
        let result = precompute.compute(&pow);
        assert_eq!(result, BigInt::mod_pow(&base, &pow, &modulo));

        let pow = BigInt::from(5);
        let result = precompute.compute(&pow);
        assert_eq!(result, BigInt::mod_pow(&base, &pow, &modulo));

        let pow = BigInt::from(20);
        let result = precompute.compute(&pow);
        assert_eq!(result, BigInt::mod_pow(&base, &pow, &modulo));

        let pow = BigInt::from(1000);
        let result = precompute.compute(&pow);
        assert_eq!(result, BigInt::mod_pow(&base, &pow, &modulo));
    }
}

// --------------------------
#[derive(Debug, PartialEq)]
pub struct Randomness(pub BigInt);

impl Randomness {
    pub fn sample(ek: &EncryptionKey) -> Randomness {
        Randomness(BigInt::sample(ek.alpha_size))
    }
}

// --------------------------

impl<'b> From<BigInt> for RawPlaintext<'b> {
    fn from(x: BigInt) -> Self {
        RawPlaintext(Cow::Owned(x))
    }
}

impl<'b> From<&'b BigInt> for RawPlaintext<'b> {
    fn from(x: &'b BigInt) -> Self {
        RawPlaintext(Cow::Borrowed(x))
    }
}

impl<'b> From<RawPlaintext<'b>> for BigInt {
    fn from(x: RawPlaintext<'b>) -> Self {
        x.0.into_owned()
    }
}

impl<'b> From<BigInt> for RawCiphertext<'b> {
    fn from(x: BigInt) -> Self {
        RawCiphertext(Cow::Owned(x))
    }
}

impl<'b> From<&'b BigInt> for RawCiphertext<'b> {
    fn from(x: &'b BigInt) -> Self {
        RawCiphertext(Cow::Borrowed(x))
    }
}

impl<'b> From<RawCiphertext<'b>> for BigInt {
    fn from(x: RawCiphertext<'b>) -> Self {
        x.0.into_owned()
    }
}


// --------------------------

// impl Serialize for EncryptionKey {
//     fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
//         let minimal = MinimalEncryptionKey::from(self);
//         minimal.serialize(serializer)
//     }
// }

// impl<'de> Deserialize<'de> for EncryptionKey {
//     fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
//         let minimal = MinimalEncryptionKey::deserialize(deserializer)?;
//         Ok(EncryptionKey::from(minimal))
//     }
// }

// impl Serialize for DecryptionKey {
//     fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
//         let minimal = MinimalDecryptionKey::from(self);
//         minimal.serialize(serializer)
//     }
// }

// impl<'de> Deserialize<'de> for DecryptionKey {
//     fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
//         let minimal = MinimalDecryptionKey::deserialize(deserializer)?;
//         Ok(DecryptionKey::from(minimal))
//     }
// }

// --------------------------
// internal functions, will be used in encoding/integral
// execute on raw plaintext and raw ciphertext

impl<'m, 'd> Encrypt<EncryptionKey, RawPlaintext<'m>, RawCiphertext<'d>> for OptimizedPaillier {
    fn encrypt(ek: &EncryptionKey, m: RawPlaintext<'m>) -> RawCiphertext<'d> {
        let r = Randomness::sample(ek);
        // rn = hn^r (mod n^2)
        let rn = BigInt::mod_pow(&ek.hn, &r.0, &ek.nn);

        // gm = (1 + m*n) (mod n^2)
        let gm: BigInt = (m.0.borrow() as &BigInt * &ek.n + 1) % &ek.nn;

        let c = (gm * rn) % &ek.nn;

        RawCiphertext(Cow::Owned(c))
    }
}

impl<'c, 'm> Decrypt<DecryptionKey, RawCiphertext<'c>, RawPlaintext<'m>> for OptimizedPaillier {
    fn decrypt(dk: &DecryptionKey, c: RawCiphertext<'c>) -> RawPlaintext<'m> {
        // l(c^(2*alpha mod n^2), n)
        let dc = BigInt::mod_pow(&c.0, &(2 * &dk.alpha), &dk.nn) - 1;
        let lc = BigInt::div_ceil(&dc, &dk.n); // l(u,n) = (u - 1) / n

        // (2* alpha)^(-1) (mod n)
        let inv_alpha = BigInt::mod_inv(&(2 * &dk.alpha), &dk.n).unwrap();

        // m = l(c^(2*alpha mod n^2), n) * (2* alpha)^(-1) (mod n)
        let m = BigInt::mod_mul(&lc, &inv_alpha, &dk.n);
        RawPlaintext(Cow::Owned(m))
    }
}

// Faster decryption
impl<'c, 'm> DecryptCRT<DecryptionKey, RawCiphertext<'c>, RawPlaintext<'m>> for OptimizedPaillier {
    fn decrypt_crt(dk: &DecryptionKey, c: RawCiphertext<'c>) -> RawPlaintext<'m> {
        // m = [l(c^(2*alpha) mod n^2, n) * inv_2alpha] mod n
        // where:
        // l(u,n) = (u - 1)/n (mod n)
        // inv_2alpha = (2*alpha)^(-1) mod n
        // n = qp, p and q are primes

        // mp = [l(c^(2*alpha) mod p^2, p) * inv_2alpha] mod p
        // mq = [l(c^(2*alpha) mod q^2, q) * inv_2alpha] mod q

        let dk_qq = &dk.q * &dk.q; // q^2
        let dk_pp = &dk.p * &dk.p; // p^2
        let dk_pinv = BigInt::mod_inv(&dk.p, &dk.q).unwrap();
        let dk_double_alpha = 2 * &dk.alpha;
        let dk_hp = h(&dk_double_alpha, &dk.p); // (2.alpha)^(-1) mod p
        let dk_hq = h(&dk_double_alpha, &dk.q); // (2.alpha)^(-1) mod q
                                                // cp = c % p^2; cq = c % q^2
        let (cp, cq) = crt_decompose(c.0.borrow(), &dk_pp, &dk_qq);
        // decrypt in parallel with respectively p and q
        // mp: decrypt, replace all n --> p
        // mq: decrypt, replace all n --> q
        let (mp, mq) = join(
            || {
                // process using p
                let dp = BigInt::mod_pow(&cp, &dk_double_alpha, &dk_pp);
                let lp = l(&dp, &dk.p);
                (&lp * &dk_hp) % &dk.p
            },
            || {
                // process using q
                let dq = BigInt::mod_pow(&cq, &dk_double_alpha, &dk_qq);
                let lq = l(&dq, &dk.q);
                (&lq * &dk_hq) % &dk.q
            },
        );
        // perform CRT
        let m = crt_recombine(mp, mq, &dk.p, &dk.q, &dk_pinv);
        RawPlaintext(Cow::Owned(m))
    }
}

// ----------------------- CRT utils

fn h(double_alpha: &BigInt, p: &BigInt) -> BigInt {
    // compute (2.alpha)^(-1) mod p^2
    BigInt::mod_inv(&double_alpha, p).unwrap()
}

fn l(u: &BigInt, n: &BigInt) -> BigInt {
    (u - 1) / n
}

fn crt_decompose<X, M1, M2>(x: X, m1: M1, m2: M2) -> (BigInt, BigInt)
where
    X: Borrow<BigInt>,
    M1: Borrow<BigInt>,
    M2: Borrow<BigInt>,
{
    (x.borrow() % m1.borrow(), x.borrow() % m2.borrow())
}

fn crt_recombine<X1, X2, M1, M2, I>(x1: X1, x2: X2, m1: M1, m2: M2, m1inv: I) -> BigInt
where
    X1: Borrow<BigInt>,
    X2: Borrow<BigInt>,
    M1: Borrow<BigInt>,
    M2: Borrow<BigInt>,
    I: Borrow<BigInt>,
{
    let diff = BigInt::mod_sub(x2.borrow(), x1.borrow(), m2.borrow());

    let u = (diff * m1inv.borrow()) % m2.borrow();
    x1.borrow() + (u * m1.borrow())
}

// /// Extract randomness component of a zero ciphertext.
// pub fn extract_nroot(dk: &DecryptionKey, z: &BigInt) -> BigInt {
//     let dk_n = &dk.p * &dk.q;

//     let dk_pinv = BigInt::mod_inv(&dk.p, &dk.q).unwrap();
//     let dk_qminusone = &dk.q - BigInt::one();
//     let dk_pminusone = &dk.p - BigInt::one();

//     let dk_phi = &dk_pminusone * &dk_qminusone;
//     let dk_dn = BigInt::mod_inv(&dk_n, &dk_phi).unwrap();
//     let (dk_dp, dk_dq) = crt_decompose(dk_dn, &dk_pminusone, &dk_qminusone);
//     let (zp, zq) = crt_decompose(z, &dk.p, &dk.q);

//     let rp = BigInt::mod_pow(&zp, &dk_dp, &dk.p);
//     let rq = BigInt::mod_pow(&zq, &dk_dq, &dk.q);

//     crt_recombine(rp, rq, &dk.p, &dk.q, &dk_pinv)
// }

// -------------------------------------

// Add and mul functions on raw plaintext and ciphertext

impl<'c1, 'c2, 'd> Add<EncryptionKey, RawCiphertext<'c1>, RawCiphertext<'c2>, RawCiphertext<'d>>
    for OptimizedPaillier
{
    fn add(
        ek: &EncryptionKey,
        c1: RawCiphertext<'c1>,
        c2: RawCiphertext<'c2>,
    ) -> RawCiphertext<'d> {
        let d = (c1.0.borrow() as &BigInt * c2.0.borrow() as &BigInt) % &ek.nn;
        RawCiphertext(Cow::Owned(d))
    }
}

impl<'c, 'm, 'd> Add<EncryptionKey, RawCiphertext<'c>, RawPlaintext<'m>, RawCiphertext<'d>>
    for OptimizedPaillier
{
    fn add(ek: &EncryptionKey, c: RawCiphertext<'c>, m: RawPlaintext<'m>) -> RawCiphertext<'d> {
        let c1 = c.0.borrow() as &BigInt;
        let c2 = (m.0.borrow() as &BigInt * &ek.n + 1) % &ek.nn;
        let d = (c1 * c2) % &ek.nn;
        RawCiphertext(Cow::Owned(d))
    }
}

impl<'c, 'm, 'd> Add<EncryptionKey, RawPlaintext<'m>, RawCiphertext<'c>, RawCiphertext<'d>>
    for OptimizedPaillier
{
    fn add(ek: &EncryptionKey, m: RawPlaintext<'m>, c: RawCiphertext<'c>) -> RawCiphertext<'d> {
        let c1 = (m.0.borrow() as &BigInt * &ek.n + 1) % &ek.nn;
        let c2 = c.0.borrow() as &BigInt;
        let d = (c1 * c2) % &ek.nn;
        RawCiphertext(Cow::Owned(d))
    }
}

impl<'c, 'm, 'd> Mul<EncryptionKey, RawCiphertext<'c>, RawPlaintext<'m>, RawCiphertext<'d>>
    for OptimizedPaillier
{
    fn mul(ek: &EncryptionKey, c: RawCiphertext<'c>, m: RawPlaintext<'m>) -> RawCiphertext<'d> {
        RawCiphertext(Cow::Owned(BigInt::mod_pow(
            c.0.borrow(),
            m.0.borrow(),
            &ek.nn,
        )))
    }
}

impl<'c, 'm, 'd> Mul<EncryptionKey, RawPlaintext<'m>, RawCiphertext<'c>, RawCiphertext<'d>>
    for OptimizedPaillier
{
    fn mul(ek: &EncryptionKey, m: RawPlaintext<'m>, c: RawCiphertext<'c>) -> RawCiphertext<'d> {
        RawCiphertext(Cow::Owned(BigInt::mod_pow(
            c.0.borrow(),
            m.0.borrow(),
            &ek.nn,
        )))
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::optimized_paillier::NGen;

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

    // #[test]
    // fn test_key_serialization() {
    //     todo!()
    // }

    // #[test]
    // fn test_failing_deserialize() {
    //     todo!()
    // }
}
