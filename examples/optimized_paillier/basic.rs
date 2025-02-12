mod test;
mod test_produce_redis;
mod server;
mod client;

use serde_json::json;
use kzen_paillier::optimized_paillier::*;

fn main() {
    // first generate a fresh keypair, where
    // the encryption key can be made public
    // while the decryption key should remain private
    println!("key gen...");
    let (ek, dk) = OptimizedPaillier::ngen(15, 10).keys();
    let result = json!({
        "encryptionKey": ek,
        "decryptionKey": dk
    });
    println!("key gen...{}", result);
    // serde_wasm_bindgen::to_value(&result).unwrap();/
    // after sharing the encryption key anyone can encrypt values
    println!("encrypt...");
    let c1 = OptimizedPaillier::encrypt(&ek, 10);
    let c2 = OptimizedPaillier::encrypt(&ek, 20);
    let c3 = OptimizedPaillier::encrypt(&ek, 30);
    let c4 = OptimizedPaillier::encrypt(&ek, 40);
    
    // and anyone can perform homomorphic operations on encrypted values,
    // e.g. multiplication with unencrypted values
    println!("mul...");
    let d1 = OptimizedPaillier::mul(&ek, c1, 4);
    let d2 = OptimizedPaillier::mul(&ek, c2, 3);
    let d3 = OptimizedPaillier::mul(&ek, c3, 2);
    let d4 = OptimizedPaillier::mul(&ek, c4, 1);
    // ... or addition with encrypted values
    println!("add...");
    let d = OptimizedPaillier::add(&ek, OptimizedPaillier::add(&ek, d1, d2), OptimizedPaillier::add(&ek, d3, d4));
    
    // after all homomorphic operations are done the result
    // should be re-randomized to hide all traces of the inputs
    // let d = OptimizedPaillier::rerandomize(&ek, d);
    
    // finally, only the one with the private decryption key
    // can retrieve the result
    println!("decrypt...");
    let m = OptimizedPaillier::decrypt(&dk, &d);
    println!("Decrypted value is {}", m);
}
