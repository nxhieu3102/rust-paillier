mod helpers;
use bencher::benchmark_main;

mod bench {

    use bencher::{benchmark_group, Bencher};
    use kzen_paillier::{paillier::Paillier, traits::KeyGeneration};
    use crate::helpers::*;

    pub fn bench_key_generation<KS: KeySize>(b: &mut Bencher) {
        b.iter(|| {
            Paillier::keypair_with_modulus_size(KS::size());
        });
    }

    benchmark_group!(
        group,
        self::bench_key_generation<KeySize512>,
        self::bench_key_generation<KeySize1024>,
        self::bench_key_generation<KeySize2048>,
        self::bench_key_generation<KeySize3072>,
        self::bench_key_generation<KeySize4096>
    );
}

benchmark_main!(bench::group);
