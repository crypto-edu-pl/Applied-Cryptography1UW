// src/lib.rs

pub mod demos;
pub mod cracker;
pub mod crypto;
pub mod utils;

// Re-export common types for easier access
pub use cracker::{Cracker, CrackResult};