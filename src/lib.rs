pub mod serialize;
pub mod primesample;
pub mod paillier;
pub mod optimized_paillier;

pub use curv::arithmetic::BigInt;
use wasm_bindgen::prelude::wasm_bindgen;
pub use primesample::*;
use crate::optimized_paillier::*;
use serde_json::json;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn ngen(n: i32, b: i32) -> JsValue {
    let (ek, dk) = OptimizedPaillier::ngen(n, b).keys();

    let result = json!({
        "encryptionKey": ek,
        "decryptionKey": dk
    });

    JsValue::from_serde(&result).unwrap()
}

#[link(wasm_import_module = "env")]
extern "C" {
    pub fn ___gmpz_sizeinbase(x: *const i32, base: i32) -> i32;
    pub fn ___gmpz_init(x: *mut i32);
    pub fn ___gmpz_clear(x: *mut i32);
    pub fn ___gmpz_get_str(str_ptr: *mut u8, base: i32, x: *const i32) -> *mut u8;
}
