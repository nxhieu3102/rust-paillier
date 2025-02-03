mod helpers;

use bencher::{benchmark_group, benchmark_main, Bencher};
use kzen_paillier::optimized_paillier::*;
use crate::helpers::*;
pub fn bench_pre_compute<KS: NKeySize>(b: &mut Bencher) {
    let params = KS::pgen(4);
    b.iter(|| {
        let _ = PrecomputeTable::new(params.g.clone(), params.block_size, params.pow_size, params.modulo.clone());
    });
}

pub fn bench_pre_compute_dp<KS: NKeySize>(b: &mut Bencher) {
    let params = KS::pgen(4);
    b.iter(|| {
        let _ = PrecomputeTable::new_dp(params.g.clone(), params.block_size, params.pow_size, params.modulo.clone());
    });
}

benchmark_group!(
    ks_2048,
    self::bench_pre_compute<NKeySize2048>,
    self::bench_pre_compute_dp<NKeySize2048>
);
benchmark_group!(
    ks_3072,
    self::bench_pre_compute<NKeySize3072>,
    self::bench_pre_compute_dp<NKeySize3072>
);


benchmark_main!(ks_2048, ks_3072);
