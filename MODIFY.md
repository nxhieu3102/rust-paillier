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

## Sample NGen
```
==================================
gen_time = 234
p = 2101691299
q = 465613451
div_p = 38821
div_q = 51449
alpha_size = 32
n_size = 64
===================================
```

```
===========================================================
gen_time = 11195
p = 58840286422659759040264722526723163115947585338232456760625037250347772947158924579397568010160401824142812407358290596642469990113927112749530655037092283267003056548558029709374658607773847180644927643815153088281601855305598381448858360794678123176275437646277062199420220697194572706984411597767662174219
q = 64569320288008737248616342555880093394368754507783709070327116553058977898351053473313292166959127254971093796968717357648354685162478156927773865332477516856906959367256797593402514551692581319610393653175392375527614160563282643144940815153885487175996514917461421149259641826709133924683180923570779884947
div_p = 15020304164245057288431929989769857115735852482951590711910706652979
div_q = 21291950558579076623582777617978449486334160877503898213693845753489
alpha_size = 448
n_size = 2048
===========================================================
```

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
