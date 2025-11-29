use crate::{
    aes::{Aes128Key, decrypt_block, encrypt_block},
    blocks::AesBlocks,
};
use rand::RngCore;

pub struct Iv([u8; 16]);

impl Iv {
    pub fn new_random() -> Self {
        let mut rng = rand::rng();
        let mut iv = [0_u8; 16];
        rng.fill_bytes(&mut iv);
        Iv(iv)
    }
}

pub struct CbcEncryptedBlocks {
    pub iv: [u8; 16],
    pub ciphertext: AesBlocks,
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
        iv: iv.0,
        ciphertext: AesBlocks::new(ciphertext_blocks).unwrap(),
    }
}

pub fn decrypt(ciphertext_blocks: &CbcEncryptedBlocks, key: &Aes128Key) -> AesBlocks {
    let mut previous_ciphertext = ciphertext_blocks.iv;
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
