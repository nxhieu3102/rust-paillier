# MODIFY NOTE

## Getting started
* Date: 23/11/2024
* `cargo build`: passed
* `cargo test`: passed
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

## Import crate for `benches`
* Date: 23/11/2024
* `use crate::helpers::*` instead of `use helpers::*;` because of Rust 2018 changed rules of path and module system [[read more](https://doc.rust-lang.org/edition-guide/rust-2018/path-changes.html)]
* Import `bencher` submodules
