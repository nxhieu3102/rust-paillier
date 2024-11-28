mod helpers;
use bencher::benchmark_main;

mod bench {

    use bencher::{benchmark_group, Bencher};
    use kzen_paillier::paillier::*;
    use kzen_paillier::optimized_paillier::*;
    use crate::helpers::*;

    pub fn bench_key_generation<KS: KeySize>(b: &mut Bencher) {
        b.iter(|| {
            Paillier::keypair_with_modulus_size(KS::size());
        });
    }

    benchmark_group!(
        group,
        bench_key_generation::<KeySize512>,
        bench_key_generation::<KeySize1024>,
        bench_key_generation::<KeySize2048>,
        bench_key_generation::<KeySize3072>,
        bench_key_generation::<KeySize4096>
    );

    pub fn bench_key_generation_safe_primes<KS: KeySize>(b: &mut Bencher) {
        b.iter(|| {
            Paillier::keypair_safe_primes_with_modulus_size(KS::size());
        });
    }

    benchmark_group!(
        group_safe_primes,
        bench_key_generation_safe_primes::<KeySize512>,
        bench_key_generation_safe_primes::<KeySize1024>,
        bench_key_generation_safe_primes::<KeySize2048>,
        bench_key_generation_safe_primes::<KeySize3072>,
        bench_key_generation_safe_primes::<KeySize4096>
    );

    use kzen_paillier::optimized_paillier::*;
    pub fn bench_key_gen_optimized_pailler<NBit: KeySize, ABit: KeySize>(b: &mut Bencher) {
        b.iter(|| {
            OptimizedPaillier::ngen_with_modulus_size(NBit::size(), ABit::size());
        });
    }

    benchmark_group!(
        group_optimized_paillier,
        bench_key_gen_optimized_pailler::<KeySize2048, KeySize448>,
        bench_key_gen_optimized_pailler::<KeySize3072, KeySize512>,
        bench_key_gen_optimized_pailler::<KeySize7680, KeySize768>
    );
}

benchmark_main!(bench::group,
    bench::group_safe_primes,
    bench::group_optimized_paillier
);