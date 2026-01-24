use super::utils::modexp;
use num_bigint::BigUint;
use std::fmt;

/// RSA Public Key - can be freely shared
#[derive(Clone)]
pub struct PublicKey {
    e: BigUint,
    n: BigUint,
}

impl PublicKey {
    pub(crate) fn new(e: BigUint, n: BigUint) -> Self {
        Self { e, n }
    }

    /// Get the public exponent e
    pub fn e(&self) -> &BigUint {
        &self.e
    }

    /// Get the modulus n
    pub fn n(&self) -> &BigUint {
        &self.n
    }

    /// Encrypt a message: c = m^e mod n
    pub fn encrypt(&self, m: &BigUint) -> BigUint {
        assert!(m < &self.n, "Message must be smaller than modulus n");
        modexp(m, &self.e, &self.n)
    }

    /// Encrypt a string by converting it to a number
    /// The string is converted to hex bytes and interpreted as a big integer
    pub fn encrypt_string(&self, s: &str) -> BigUint {
        let bytes = s.as_bytes();
        let m = BigUint::from_bytes_be(bytes);
        assert!(
            m < self.n,
            "String too long for this key size (message {} bits, modulus {} bits)",
            m.bits(),
            self.n.bits()
        );
        self.encrypt(&m)
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PublicKey")
            .field("e", &self.e)
            .field("n", &self.n)
            .finish()
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey(e={}, n={})", self.e, self.n)
    }
}
