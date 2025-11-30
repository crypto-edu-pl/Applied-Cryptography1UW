#![allow(deprecated)]

use aes::Aes128;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use generic_array::GenericArray;
use rand::RngCore;
pub struct Aes128Key([u8; 16]);

impl Aes128Key {
    pub fn new_random() -> Self {
        let mut rng = rand::rng();
        let mut key = [0_u8; 16];
        rng.fill_bytes(&mut key);
        Aes128Key(key)
    }
}

pub fn encrypt_block(plaintext: &[u8; 16], key: &Aes128Key) -> Box<[u8; 16]> {
    let key = GenericArray::from(key.0);
    let mut block = GenericArray::from(*plaintext);

    let cipher = Aes128::new(&key);

    cipher.encrypt_block(&mut block);

    Box::new(block.into())
}

pub fn decrypt_block(ciphertext: &[u8; 16], key: &Aes128Key) -> Box<[u8; 16]> {
    let key = GenericArray::from(key.0);
    let mut block = GenericArray::from(*ciphertext);

    let cipher = Aes128::new(&key);

    cipher.decrypt_block(&mut block);

    Box::new(block.into())
}
