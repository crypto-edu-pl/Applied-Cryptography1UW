use std::fmt::Debug;

use crate::{
    aes::{Aes128Key, decrypt_block, encrypt_block},
    blocks::AesBlocks,
};
use rand::RngCore;

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

impl Debug for Iv {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in self.0.iter() {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct CbcEncryptedBlocks {
    pub iv: Iv,
    pub ciphertext: AesBlocks,
}

impl CbcEncryptedBlocks {
    pub fn to_full_message(&self) -> AesBlocks {
        let mut full_message = self.iv.0.to_vec();
        full_message.extend(self.ciphertext.iter());
        AesBlocks::new(full_message).unwrap()
    }

    pub fn from_full_message(full_message: &AesBlocks) -> Self {
        let mut iter = full_message.iter().copied();
        let iv = Iv::new_unchecked(
            iter.by_ref()
                .take(16)
                .collect::<Vec<u8>>()
                .try_into()
                .unwrap(),
        );
        let ciphertext = AesBlocks::new(iter.collect()).unwrap();
        CbcEncryptedBlocks { iv, ciphertext }
    }
}

pub fn encrypt(plaintext_blocks: &AesBlocks, iv: &Iv, key: &Aes128Key) -> CbcEncryptedBlocks {
    let mut previous_ciphertext = iv.0;
    let mut ciphertext_blocks = Vec::new();
    for block in plaintext_blocks.iter_blocks() {
        let xor_block = xor_blocks(block, &previous_ciphertext);
        let encrypted_block = encrypt_block(&xor_block, key);
        ciphertext_blocks.extend(encrypted_block.iter());
        previous_ciphertext = *encrypted_block;
    }
    CbcEncryptedBlocks {
        iv: iv.clone(),
        ciphertext: AesBlocks::new(ciphertext_blocks).unwrap(),
    }
}

pub fn decrypt(ciphertext_blocks: &CbcEncryptedBlocks, key: &Aes128Key) -> AesBlocks {
    let mut previous_ciphertext = ciphertext_blocks.iv.0;
    let mut plaintext_blocks = Vec::new();
    for block in ciphertext_blocks.ciphertext.iter_blocks() {
        let decrypted_block = decrypt_block(block, key);
        let xor_block = xor_blocks(&decrypted_block, &previous_ciphertext);
        plaintext_blocks.extend(xor_block.iter());
        previous_ciphertext = *block;
    }
    AesBlocks::new(plaintext_blocks).unwrap()
}

fn xor_blocks(block1: &[u8; 16], block2: &[u8; 16]) -> [u8; 16] {
    let mut xor_block = [0_u8; 16];
    for ((out, b1), b2) in xor_block.iter_mut().zip(block1.iter()).zip(block2.iter()) {
        *out = b1 ^ b2;
    }
    xor_block
}
