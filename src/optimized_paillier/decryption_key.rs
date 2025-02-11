use std::borrow::{Borrow, Cow};
use curv::arithmetic::{Integer, Modulo};
use curv::BigInt;
use crate::optimized_paillier::{Decrypt, DecryptCRT, DecryptionKey, OptimizedPaillier, RawCiphertext, RawPlaintext};
use rayon::join;

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