use curv::arithmetic::Samplable;
use curv::arithmetic::traits::*;
use crate::optimized_paillier::traits::KeyGeneration;

use super::{NGen, OptimizedPaillier};
use crate::{are_all_primes, check_coprime, BigInt, PrimeSampable};

use std::io::{Read, Write};

use std::fs::{File, OpenOptions};
use serde::Serialize; // To enable serialization for structs
use serde_json::{self, Value, Map};

#[derive(Serialize)] // Make the struct serializable to JSON
struct OutputData {
    retry_times: usize,
    elapsed_time: String,
    p: String,
    q: String,
    div_p: String,
    div_q: String,
    alpha_size: usize,
    n_size: usize,
}

impl KeyGeneration<NGen> for OptimizedPaillier {
    fn ngen_with_modulus_size(mut n_bit_length: usize,mut  alpha_bit_length: usize) -> NGen {
        println!("start key gen with {} {}", n_bit_length, alpha_bit_length);
        let mut count = 0;
        let start_time = Instant::now(); // Record start time
        loop {
            count += 1;
            if count % 100000 == 0 {
                println!("retry times = {:?}", count);
            }
            let div_p = BigInt::sample_prime(alpha_bit_length / 2);
            let div_q = BigInt::sample_prime(alpha_bit_length / 2);

            let other_bit_length = (n_bit_length - alpha_bit_length) / 2 - 1;
            let mut other_div_p = BigInt::sample(other_bit_length);
            let mut other_div_q = BigInt::sample(other_bit_length);

            // We flip the LSB to make sure tue candidate is odd.
            BigInt::set_bit(&mut other_div_p, 0, true);
            BigInt::set_bit(&mut other_div_q, 0, true);

            let p = 2 * &div_p * &other_div_p + 1;
            let q = 2 * &div_q * &other_div_q + 1;

            if are_all_primes(&[&p, &q])
                && check_coprime(&[&div_p, &div_q, &other_div_p, &other_div_q])
            {
                let duration = start_time.elapsed(); // Calculate elapsed time
                println!("===========================================================");
                println!("retry times = {:?}", count);
                println!("elapsed_time = {:?}", duration);
                println!("p = {:?}", p);
                println!("q = {:?}", q);
                println!("div_p = {:?}", div_p);
                println!("div_q = {:?}", div_q);
                println!("alpha_size = {:?}", alpha_bit_length);
                println!("n_size = {:?}", n_bit_length);
                println!("===========================================================");

                // Create a serializable struct
                let output_data = OutputData {
                    retry_times: count,
                    elapsed_time: format!("{:?}", duration),
                    p: format!("{:?}", p),
                    q: format!("{:?}", q),
                    div_p: format!("{:?}", div_p),
                    div_q: format!("{:?}", div_q),
                    alpha_size: alpha_bit_length,
                    n_size: n_bit_length,
                };

                let file_path = format!("benches/results/{}_{}.json", n_bit_length, alpha_bit_length);
                let mut current_json = Map::new();

                // Read and parse existing JSON
                if let Ok(mut file) = File::open(file_path.clone()) {
                    let mut contents = String::new();
                    file.read_to_string(&mut contents).unwrap_or_default();
                    current_json = serde_json::from_str(&contents).unwrap_or_else(|_| {
                        let mut map = Map::new();
                        map.insert("results".to_string(), Value::Array(vec![]));
                        map
                    });
                } else {
                    // Initialize JSON if file doesn't exist
                    current_json.insert("results".to_string(), Value::Array(vec![]));
                }

                // Append new data to results array
                if let Some(results) = current_json.get_mut("results").and_then(Value::as_array_mut) {
                    results.push(serde_json::to_value(output_data).unwrap());
                }

                // Write updated JSON back to file
                if let Ok(mut file) = OpenOptions::new()
                    .create(true)
                    .write(true)
                    .truncate(true) // Overwrite file
                    .open(file_path)
                {
                    if let Err(e) = file.write_all(serde_json::to_string_pretty(&current_json).unwrap().as_bytes()) {
                        eprintln!("Failed to write to file: {:?}", e);
                    }
                } else {
                    eprintln!("Failed to open or create file for writing.");
                }

                return NGen {
                    n: &p * &q,
                    p,
                    q,
                    div_p,
                    div_q,
                    alpha_size: alpha_bit_length,
                };
            }
        }
    }

    fn ngen_safe_primes_with_modulus_size(n_bit_length: usize, alpha_bit_length: usize) -> NGen {
        // TODO: set max loop
        loop {
            let div_p = BigInt::sample_safe_prime(alpha_bit_length / 2);
            let div_q = BigInt::sample_safe_prime(alpha_bit_length / 2);

            let other_bit_length = (n_bit_length - alpha_bit_length) / 2 - 1;
            let mut other_div_p = BigInt::sample(other_bit_length);
            let mut other_div_q = BigInt::sample(other_bit_length);

            // We flip the LSB to make sure tue candidate is odd.
            BigInt::set_bit(&mut other_div_p, 0, true);
            BigInt::set_bit(&mut other_div_q, 0, true);

            let p = 2 * &div_p * &other_div_p + 1;
            let q = 2 * &div_q * &other_div_q + 1;

            if are_all_primes(&[&p, &q])
                && check_coprime(&[&div_p, &div_q, &other_div_p, &other_div_q])
            {
                return NGen {
                    n: &p * &q,
                    p,
                    q,
                    div_p,
                    div_q,
                    alpha_size: alpha_bit_length,
                };
            }
        }
    }
}
