use num_bigint::BigUint;
use num_traits::{One, Zero};
use sha2::{Digest, Sha256};

/// Modular exponentiation using square-and-multiply algorithm
/// Computes (base^exp) % modulus efficiently
pub fn modexp(base: &BigUint, exp: &BigUint, modulus: &BigUint) -> BigUint {
    if modulus.is_one() {
        return BigUint::zero();
    }

    let mut result = BigUint::one();
    let mut base = base % modulus;
    let mut exp = exp.clone();

    while !exp.is_zero() {
        if &exp % 2u32 == BigUint::one() {
            result = (&result * &base) % modulus;
        }
        base = (&base * &base) % modulus;
        exp >>= 1;
    }

    result
}

/// Hash the shared secret to derive a 256-bit key
pub fn derive_key(shared_secret: &BigUint) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(shared_secret.to_bytes_be());
    hasher.finalize().to_vec()
}
