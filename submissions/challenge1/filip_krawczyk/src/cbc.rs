use crate::{
    aes::{Aes128Key, decrypt_block, encrypt_block},
    blocks::AesBlocks,
};

pub fn encrypt(
    plaintext_blocks: &AesBlocks,
    iv: &[u8; 16],
    key: &Aes128Key,
) -> (AesBlocks, [u8; 16]) {
    let mut previous_ciphertext = *iv;
    let mut ciphertext_blocks = Vec::new();
    for block in plaintext_blocks.iter_blocks() {
        let xor_block = xor_blocks(block, &previous_ciphertext);
        let encrypted_block = encrypt_block(&xor_block, key);
        ciphertext_blocks.extend(encrypted_block.iter());
        previous_ciphertext = *encrypted_block;
    }
    (
        AesBlocks::new(ciphertext_blocks).unwrap(),
        previous_ciphertext,
    )
}

pub fn decrypt(ciphertext_blocks: &AesBlocks, iv: &[u8; 16], key: &Aes128Key) -> AesBlocks {
    let mut previous_ciphertext = *iv;
    let mut plaintext_blocks = Vec::new();
    for block in ciphertext_blocks.iter_blocks() {
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
