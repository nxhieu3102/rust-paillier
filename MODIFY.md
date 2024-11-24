# MODIFY NOTE

## Getting started
* Date: 24/11/2024
* `cargo build`: passed
* `cargo test`: passed
* Paillier (from kzen)
    * Benchmark:
        * `cargo bench --bench arith`: passed
        * `cargo bench --bench keygen`: passed
        * `cargo bench --bench encryption`: passed
        * `cargo bench --bench proof`: failed, could not find `proof` in `kzen_paillier`
        * `cargo bench`: benchmark all failed
    * Run examples: 
        * `cargo run --example basic`: passed
        * `cargo run --example core`: passed
        * `cargo run --example packed`: passed
        * `cargo run --example simple-voting`: passed
* Optimized Paillier (empty)

## Implementation
* DONE: key gen, encrypt, decrypt, add, mul 
* TODO:
    * test
    * benchmarks
    * example
* ERROR:
    * `is_prime` always returns `false`???

## Init Optimized Paillier (lib)
* Date: 24/11/2024
* lib directory: `src/optimized_paillier`
* `mod.rs`: declare sub-modules and structs
* `traits.rs`: interfaces for Optimized Paillier (don't need to read)
* [TODO] `core/`: internal functions, which execute on raw plaintext and ciphertext (`BigInt`)
* [TODO] `keygen.rs`: entry point of key generation
* [TODO] `encoding/integral.rs`: entry point of get key, encrypt, decrypt, add, mul... features; use functions in `core/` 

> Many functions are unimplemented, so `cargo build` will raise many warnings. You don't need to fix them :>

## Restructure `kzen` project
* Date: 24/11/2024
* Restructure the kzen lib to add Optimized Paillier
* `traits` and `serialize` are common components
* `optimized_paillier` is a sub-module of `kzen` lib (as `paillier`)
* `optimized_paillier` will implement all traits in `traits.rs`

## Import crate for `benches`
* Date: 23/11/2024
* `use crate::helpers::*` instead of `use helpers::*;` because of Rust 2018 changed rules of path and module system [[read more](https://doc.rust-lang.org/edition-guide/rust-2018/path-changes.html)]
* Import `bencher` submodules
