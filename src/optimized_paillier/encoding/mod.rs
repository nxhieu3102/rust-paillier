pub mod integral;

use std::marker::PhantomData;

use serde::{Deserialize, Serialize};

use curv::BigInt;

/// Encrypted message with type information.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EncodedCiphertext<T> {
    // #[serde(with = "crate::serialize::bigint")]
    pub raw: BigInt,
    pub components: usize,
    pub _phantom: PhantomData<T>,
}
