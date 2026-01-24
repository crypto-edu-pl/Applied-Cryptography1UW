use super::public_key::PublicKey;
use super::utils::{invmod, modexp};
use num_bigint::BigUint;
use num_prime::RandPrime;
use num_traits::One;
use rand::Rng;
use std::fmt;

/// RSA Key Pair - contains both public and private keys
/// The private key (d) is never exposed directly
pub struct KeyPair {
    /// Private exponent - NEVER expose this
    d: BigUint,
    /// Public key (e, n) - can be shared freely
    public_key: PublicKey,
}

impl KeyPair {
    /// Generate a new RSA key pair with the given bit size for primes
    /// Uses e = 3 as the public exponent
    pub fn generate<R: Rng>(rng: &mut R, prime_bits: usize) -> Self {
        Self::generate_with_e(rng, prime_bits, BigUint::from(3u32))
    }

    /// Generate a new RSA key pair with custom public exponent
    pub fn generate_with_e<R: Rng>(rng: &mut R, prime_bits: usize, e: BigUint) -> Self {
        loop {
            let p: BigUint = rng.gen_prime(prime_bits, None);
            let q: BigUint = rng.gen_prime(prime_bits, None);

            // Ensure p != q
            if p == q {
                continue;
            }

            let n = &p * &q;

            // et = (p-1) * (q-1) - Euler's totient
            let p_minus_1 = &p - BigUint::one();
            let q_minus_1 = &q - BigUint::one();
            let et = &p_minus_1 * &q_minus_1;

            // Compute d = invmod(e, et)
            // This may fail if gcd(e, et) != 1, so we retry with new primes
            if let Some(d) = invmod(&e, &et) {
                let public_key = PublicKey::new(e, n);
                return Self { d, public_key };
            }
        }
    }

    /// Create a key pair from known small primes (for testing)
    pub fn from_primes(p: BigUint, q: BigUint, e: BigUint) -> Option<Self> {
        let n = &p * &q;
        let p_minus_1 = &p - BigUint::one();
        let q_minus_1 = &q - BigUint::one();
        let et = &p_minus_1 * &q_minus_1;

        let d = invmod(&e, &et)?;
        let public_key = PublicKey::new(e, n);
        Some(Self { d, public_key })
    }

    /// Get the public key (can be freely shared)
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Decrypt a ciphertext: m = c^d mod n
    pub fn decrypt(&self, c: &BigUint) -> BigUint {
        modexp(c, &self.d, self.public_key.n())
    }

    /// Decrypt a ciphertext and convert back to a string
    pub fn decrypt_to_string(&self, c: &BigUint) -> Result<String, std::string::FromUtf8Error> {
        let m = self.decrypt(c);
        let bytes = m.to_bytes_be();
        String::from_utf8(bytes)
    }
}

impl fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Intentionally hide the private key d
        f.debug_struct("KeyPair")
            .field("public_key", &self.public_key)
            .field("d", &"[PRIVATE - HIDDEN]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_small_primes() {
        // p=61, q=53, e=17
        let p = BigUint::from(61u32);
        let q = BigUint::from(53u32);
        let e = BigUint::from(17u32);

        let keypair = KeyPair::from_primes(p, q, e).unwrap();
        let m = BigUint::from(42u32);

        let c = keypair.public_key().encrypt(&m);
        let decrypted = keypair.decrypt(&c);

        assert_eq!(decrypted, m);
    }

    #[test]
    fn test_encrypt_decrypt_42() {
        let mut rng = rand::thread_rng();
        let keypair = KeyPair::generate(&mut rng, 512);

        let m = BigUint::from(42u32);
        let c = keypair.public_key().encrypt(&m);
        let decrypted = keypair.decrypt(&c);

        assert_eq!(decrypted, m);
    }

    #[test]
    fn test_encrypt_string() {
        let mut rng = rand::thread_rng();
        let keypair = KeyPair::generate(&mut rng, 512);

        let message = "Hello, RSA!";
        let c = keypair.public_key().encrypt_string(message);
        let decrypted = keypair.decrypt_to_string(&c).unwrap();

        assert_eq!(decrypted, message);
    }
}
