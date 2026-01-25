// src/lib.rs

pub mod block_crypto;
pub mod cracker;
pub mod crypto_constants;
pub mod demos;
pub mod hashing;
pub mod number_theoretic_crypto;
pub mod xor;
pub mod utils;

// Re-export common types for easier access
pub use cracker::{Cracker, CrackResult};