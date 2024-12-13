mod helpers;

use bencher::{benchmark_group, benchmark_main, Bencher};
use kzen_paillier::optimized_paillier::*;
use crate::helpers::*;
pub fn bench_encryption_ek<KS: NKeySize>(b: &mut Bencher) {
    let (ek, dk) = KS::gen().keys();
    b.iter(|| {
        let _ = OptimizedPaillier::encrypt(&ek, 10);
    });
}

pub fn bench_encryption_dk<KS: NKeySize>(b: &mut Bencher) {
    let (ek, dk) = KS::gen().keys();

    b.iter(|| {
        let _ = OptimizedPaillier::encrypt(&ek, 10);
    });
}

pub fn bench_decryption<KS: NKeySize>(b: &mut Bencher) {
    let keypair = KS::gen();
    let (ek, dk) = keypair.keys();

    let c = OptimizedPaillier::encrypt(&ek, 10);

    b.iter(|| {
        let _ = OptimizedPaillier::decrypt(&dk, &c);
    });
}
//
// pub fn bench_rerandomisation<KS: KeySize>(b: &mut Bencher) {
//     let keypair = KS::keypair();
//     let ek = EncryptionKey::from(&keypair);
//
//     let c = OptimizedPaillier::encrypt(&ek, 10);
//
//     b.iter(|| {
//         let _ = OptimizedPaillier::rerandomize(&ek, &c);
//     });
// }

pub fn bench_addition<KS: NKeySize>(b: &mut Bencher) {
    let (ek, _dk) = KS::gen().keys();

    let c1 = OptimizedPaillier::encrypt(&ek, 10);
    let c2 = OptimizedPaillier::encrypt(&ek, 20);

    b.iter(|| {
        let _ = OptimizedPaillier::add(&ek, &c1, &c2);
    });
}

pub fn bench_multiplication<KS: NKeySize>(b: &mut Bencher) {
    let (ek, _dk) = KS::gen().keys();
    let c = OptimizedPaillier::encrypt(&ek, 10);

    b.iter(|| {
        let _ = OptimizedPaillier::mul(&ek, &c, 20);
    });
}

benchmark_group!(
    ks_2048,
    self::bench_encryption_ek<NKeySize2048>,
    // self::bench_encryption_dk<NKeySize2048>,
    self::bench_decryption<NKeySize2048>,
    // self::bench_rerandomisation<NKeySize2048>,
    self::bench_addition<NKeySize2048>,
    self::bench_multiplication<NKeySize2048>
);

benchmark_group!(
    ks_3072,
    self::bench_encryption_ek<NKeySize3072>,
    // self::bench_encryption_dk<NKeySize3072>,
    self::bench_decryption<NKeySize3072>,
    // self::bench_rerandomisation<NKeySize3072>,
    self::bench_addition<NKeySize3072>,
    self::bench_multiplication<NKeySize3072>
);

benchmark_main!(ks_2048, ks_3072);
