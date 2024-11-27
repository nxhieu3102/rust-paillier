pub mod integral;

use std::marker::PhantomData;

use serde::{Deserialize, Serialize};

use crate::BigInt;

/// Encrypted message with type information.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EncodedCiphertext<T> {
    #[serde(with = "crate::serialize::bigint")]
    raw: BigInt,
    components: usize,
    _phantom: PhantomData<T>,
}