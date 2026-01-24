use num_bigint::{BigUint, RandBigInt};
use rand::Rng;

/// Diffie-Hellman configuration
#[derive(Clone)]
pub struct Config {
    p: BigUint,
    g: BigUint,
}

impl Config {
    pub fn new(p: BigUint, g: BigUint) -> Self {
        Self { p, g }
    }

    /// Create config with small test parameters (p=37, g=5)
    pub fn small() -> Self {
        Self::new(BigUint::from(37u32), BigUint::from(5u32))
    }

    /// Create config with NIST 1536-bit parameters
    pub fn nist_1536() -> Self {
        let p_hex = concat!(
            "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024",
            "e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd",
            "3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec",
            "6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f",
            "24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361",
            "c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552",
            "bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff",
            "fffffffffffff"
        );
        let p = BigUint::parse_bytes(p_hex.as_bytes(), 16).expect("Failed to parse p");
        let g = BigUint::from(2u32);
        Self::new(p, g)
    }

    pub fn p(&self) -> &BigUint {
        &self.p
    }

    pub fn g(&self) -> &BigUint {
        &self.g
    }

    /// Generate a random private key in range [2, p-2]
    pub fn gen_private_key<R: Rng>(&self, rng: &mut R) -> BigUint {
        let two = BigUint::from(2u32);
        let upper = &self.p - &two;
        rng.gen_biguint_below(&upper) + &two
    }
}
