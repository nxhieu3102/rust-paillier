mod helpers;
use bencher::{benchmark_group, benchmark_main, Bencher};
use kzen_paillier::optimized_paillier::*;
use crate::helpers::*;
use crate::helpers::logger::{Logger, OutputData};
use once_cell::sync::Lazy;
use std::sync::Mutex;

static BLOCK_SIZE: usize = 10;
static PRECOMPUTE_TABLE: Lazy<Mutex<PrecomputeTable>> = Lazy::new(|| {
    let params = NKeySize2048::pgen(BLOCK_SIZE);
    Mutex::new(PrecomputeTable::new_dp(
        params.g.clone(),
        params.block_size,
        params.pow_size,
        params.modulo.clone(),
    ))
});

fn get_precompute_table<KS: NKeySize>() -> &'static Mutex<PrecomputeTable> {
    &PRECOMPUTE_TABLE
}

pub fn bench_encryption_ek<KS: NKeySize>(b: &mut Bencher) {
    let (ek, _dk) = KS::gen().keys();
    let precompute_table = get_precompute_table::<KS>();

    b.iter(|| {
        let table = precompute_table.lock().unwrap();
        let _ = OptimizedPaillier::encrypt_with_precompute_table(&*table, &ek, 10); // Dereference table
    });

    let elapsed_time = b.ns_per_iter();
    println!("Elapsed time: {}", elapsed_time);
    let file_path = "benches/optimized_paillier/benchmark_result/encryption_precompute/".to_string() + &KS::string() + ".json";
    Logger::log_benchmark_time(OutputData {
        benchmark_time: elapsed_time as usize,
        benchmark_case: "encryption_ek".to_string(),
        benchmark_params: KS::string(),
        precompute_table_block_size: BLOCK_SIZE,

    }, file_path);
}


pub fn bench_encryption_dk<KS: NKeySize>(b: &mut Bencher) {
    let (ek, dk) = KS::gen().keys();
    let precompute_table = get_precompute_table::<KS>();
    b.iter(|| {
        let table = precompute_table.lock().unwrap();
        let _ = OptimizedPaillier::encrypt_with_precompute_table(&*table, &ek, 10);
    });

    let elapsed_time = b.ns_elapsed();
    let file_path = "benches/optimized_paillier/benchmark_result/encryption_precompute/".to_string() + &KS::string() + ".json";
    Logger::log_benchmark_time(OutputData {
        benchmark_time: elapsed_time as usize,
        benchmark_case: "encryption_dk".to_string(),
        benchmark_params: KS::string(),
        precompute_table_block_size: BLOCK_SIZE,
    }, file_path);
}

pub fn bench_decryption<KS: NKeySize>(b: &mut Bencher) {
    let keypair = KS::gen();
    let (ek, dk) = keypair.keys();
    let precompute_table = get_precompute_table::<KS>();
    let table = precompute_table.lock().unwrap();
    let c = OptimizedPaillier::encrypt_with_precompute_table(&*table, &ek, 10);

    b.iter(|| {
        let _ = OptimizedPaillier::decrypt(&dk, &c);
    });

    let elapsed_time = b.ns_elapsed();
    let file_path = "benches/optimized_paillier/benchmark_result/encryption_precompute/".to_string() + &KS::string() + ".json";
    Logger::log_benchmark_time(OutputData {
        benchmark_time: elapsed_time as usize,
        benchmark_case: "decryption".to_string(),
        benchmark_params: KS::string(),
        precompute_table_block_size: BLOCK_SIZE,
    }, file_path);
}

pub fn bench_addition<KS: NKeySize>(b: &mut Bencher) {
    let (ek, _dk) = KS::gen().keys();
    let precompute_table = get_precompute_table::<KS>();
    let table = precompute_table.lock().unwrap();
    let c1 = OptimizedPaillier::encrypt_with_precompute_table(&*table, &ek, 10);
    let c2 = OptimizedPaillier::encrypt_with_precompute_table(&*table, &ek, 20);

    b.iter(|| {
        let _ = OptimizedPaillier::add(&ek, &c1, &c2);
    });

    let elapsed_time = b.ns_elapsed();
    let file_path = "benches/optimized_paillier/benchmark_result/encryption_precompute/".to_string() + &KS::string() + ".json";
    Logger::log_benchmark_time(OutputData {
        benchmark_time: elapsed_time as usize,
        benchmark_case: "addition".to_string(),
        benchmark_params: KS::string(),
        precompute_table_block_size: BLOCK_SIZE,
    }, file_path);
}

pub fn bench_multiplication<KS: NKeySize>(b: &mut Bencher) {
    let (ek, _dk) = KS::gen().keys();
    let precompute_table = get_precompute_table::<KS>();
    let table = precompute_table.lock().unwrap();
    let c = OptimizedPaillier::encrypt_with_precompute_table(&*table, &ek, 10);
    b.iter(|| {
        let _ = OptimizedPaillier::mul(&ek, &c, 20);
    });

    let elapsed_time = b.ns_elapsed();
    let file_path = "benches/optimized_paillier/benchmark_result/encryption_precompute/".to_string() + &KS::string() + ".json";
    Logger::log_benchmark_time(OutputData {
        benchmark_time: elapsed_time as usize,
        benchmark_case: "multiplication".to_string(),
        benchmark_params: KS::string(),
        precompute_table_block_size: BLOCK_SIZE,
    }, file_path);
}

benchmark_group!(
    ks_2048,
    self::bench_encryption_ek<NKeySize2048>,
    self::bench_encryption_dk<NKeySize2048>,
    self::bench_decryption<NKeySize2048>,
    self::bench_addition<NKeySize2048>,
    self::bench_multiplication<NKeySize2048>
);

benchmark_group!(
    ks_3072,
    self::bench_encryption_ek<NKeySize3072>,
    self::bench_encryption_dk<NKeySize3072>,
    self::bench_decryption<NKeySize3072>,
    self::bench_addition<NKeySize3072>,
    self::bench_multiplication<NKeySize3072>
);

benchmark_main!(ks_2048, ks_3072);
