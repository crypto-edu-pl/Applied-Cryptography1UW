use super::config::Config;
use super::utils::modexp;
use num_bigint::BigUint;
use rand::Rng;
use std::fmt;

pub struct Party {
    config: Config,
    private_key: BigUint,
    public_key: BigUint,
}

impl Party {
    pub fn new<R: Rng>(config: &Config, rng: &mut R) -> Self {
        let private_key = config.gen_private_key(rng);
        let public_key = Self::compute_public_key(config, &private_key);
        Self {
            config: config.clone(),
            private_key,
            public_key,
        }
    }

    fn compute_public_key(config: &Config, private_key: &BigUint) -> BigUint {
        modexp(config.g(), private_key, config.p())
    }

    pub fn generate_message(&self) -> BigUint {
        self.public_key.clone()
    }

    pub fn compute_shared_secret(&self, other_public_key: &BigUint) -> BigUint {
        modexp(other_public_key, &self.private_key, self.config.p())
    }
}

impl fmt::Debug for Party {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Party")
            .field("private_key", &self.private_key)
            .field("public_key", &self.public_key)
            .finish()
    }
}
