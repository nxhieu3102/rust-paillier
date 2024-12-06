mod helpers;
mod encryption;

use bencher::benchmark_main;

mod bench {

    use bencher::{benchmark_group, Bencher};
    use kzen_paillier::optimized_paillier::*;
    use crate::helpers::*;

    use kzen_paillier::optimized_paillier::*;
    pub fn bench_key_gen_optimized_pailler<NBit: KeySize, ABit: KeySize>(b: &mut Bencher) {
        b.iter(|| {
            OptimizedPaillier::ngen_with_modulus_size(NBit::size(), ABit::size());
        });
    }

    benchmark_group!(
        group_optimized_paillier,
        bench_key_gen_optimized_pailler::<KeySize2048, KeySize448>,
        // bench_key_gen_optimized_pailler::<KeySize3072, KeySize512>,
        // bench_key_gen_optimized_pailler::<KeySize7680, KeySize768>,
    );
}

benchmark_main!(
    bench::group_optimized_paillier
);