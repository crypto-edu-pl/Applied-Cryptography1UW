use rand::RngCore;
use std::{fmt::Debug, ops::Deref};

#[derive(Clone)]
pub struct Iv([u8; 16]);

impl Iv {
    pub fn new_random() -> Self {
        let mut rng = rand::rng();
        let mut iv = [0_u8; 16];
        rng.fill_bytes(&mut iv);
        Iv(iv)
    }

    pub fn new_unchecked(iv: [u8; 16]) -> Self {
        Iv(iv)
    }

    pub fn get(&self) -> &[u8; 16] {
        &self.0
    }
}

impl Deref for Iv {
    type Target = [u8; 16];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Debug for Iv {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in self.0.iter() {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}
