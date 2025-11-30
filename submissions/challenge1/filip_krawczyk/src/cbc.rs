use std::fmt::Debug;

use crate::{
    aes::{Aes128Key, decrypt_block, encrypt_block},
    blocks::AesBlocks,
    iv::Iv,
};
#[derive(Debug)]
pub struct CbcEncryptedBlocks {
    pub iv: Iv,
    pub ciphertext: AesBlocks,
}

impl CbcEncryptedBlocks {
    /// Converts iv and blocks to the full message (iv + blocks).
    pub fn to_full_message(&self) -> AesBlocks {
        let mut full_message = self.iv.to_vec();
        full_message.extend(self.ciphertext.iter());
        AesBlocks::new(full_message).unwrap()
    }

    /// Separates the full message into iv and blocks.
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
    let mut previous_ciphertext = iv.get().to_owned();
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
    let mut previous_ciphertext = ciphertext_blocks.iv.get().to_owned();
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_full_message_and_from_full_message_roundtrip() {
        let iv = Iv::new_unchecked([
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ]);
        let ciphertext = AesBlocks::new(vec![
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
            0x1e, 0x1f,
        ])
        .unwrap();

        let encrypted = CbcEncryptedBlocks {
            iv: iv.clone(),
            ciphertext: ciphertext.clone(),
        };

        let full_message = encrypted.to_full_message();
        let reconstructed = CbcEncryptedBlocks::from_full_message(&full_message);

        assert_eq!(reconstructed.iv.get(), iv.get());
        assert_eq!(reconstructed.ciphertext.as_slice(), ciphertext.as_slice());
    }

    #[test]
    fn test_to_full_message_and_from_full_message_multiple_blocks() {
        let iv = Iv::new_unchecked([0xff; 16]);
        let ciphertext = AesBlocks::new(vec![0u8; 64]).unwrap(); // 4 blocks

        let encrypted = CbcEncryptedBlocks {
            iv: iv.clone(),
            ciphertext: ciphertext.clone(),
        };

        let full_message = encrypted.to_full_message();
        assert_eq!(full_message.len(), 80); // 16 (IV) + 64 (4 blocks)

        let reconstructed = CbcEncryptedBlocks::from_full_message(&full_message);
        assert_eq!(reconstructed.iv.get(), iv.get());
        assert_eq!(reconstructed.ciphertext.as_slice(), ciphertext.as_slice());
    }

    #[test]
    fn test_encrypt_decrypt_single_block() {
        let key = Aes128Key::new_random();
        let iv = Iv::new_random();
        let plaintext = AesBlocks::new(vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ])
        .unwrap();

        let encrypted = encrypt(&plaintext, &iv, &key);
        let decrypted = decrypt(&encrypted, &key);

        assert_eq!(decrypted.as_slice(), plaintext.as_slice());
    }

    #[test]
    fn test_encrypt_decrypt_multiple_blocks() {
        let key = Aes128Key::new_random();
        let iv = Iv::new_random();
        let plaintext = AesBlocks::new(vec![0u8; 64]).unwrap(); // 4 blocks

        let encrypted = encrypt(&plaintext, &iv, &key);
        let decrypted = decrypt(&encrypted, &key);

        assert_eq!(decrypted.as_slice(), plaintext.as_slice());
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip_various_sizes() {
        let key = Aes128Key::new_random();

        for size in [16, 32, 48, 64, 80, 96] {
            let iv = Iv::new_random();
            let plaintext = AesBlocks::new(vec![0x42u8; size]).unwrap();

            let encrypted = encrypt(&plaintext, &iv, &key);
            let decrypted = decrypt(&encrypted, &key);

            assert_eq!(
                decrypted.as_slice(),
                plaintext.as_slice(),
                "Failed for size {size}"
            );
        }
    }

    #[test]
    fn test_encrypt_decrypt_different_plaintexts_same_key() {
        let key = Aes128Key::new_random();
        let iv = Iv::new_random();

        let plaintext1 = AesBlocks::new(vec![0x00u8; 32]).unwrap();
        let plaintext2 = AesBlocks::new(vec![0xFFu8; 32]).unwrap();

        let encrypted1 = encrypt(&plaintext1, &iv, &key);
        let encrypted2 = encrypt(&plaintext2, &iv, &key);

        // Different plaintexts should produce different ciphertexts
        assert_ne!(
            encrypted1.ciphertext.as_slice(),
            encrypted2.ciphertext.as_slice()
        );

        // But both should decrypt correctly
        let decrypted1 = decrypt(&encrypted1, &key);
        let decrypted2 = decrypt(&encrypted2, &key);

        assert_eq!(decrypted1.as_slice(), plaintext1.as_slice());
        assert_eq!(decrypted2.as_slice(), plaintext2.as_slice());
    }

    #[test]
    fn test_encrypt_decrypt_different_ivs_same_plaintext() {
        let key = Aes128Key::new_random();
        let plaintext = AesBlocks::new(vec![0x42u8; 32]).unwrap();

        let iv1 = Iv::new_random();
        let iv2 = Iv::new_random();

        let encrypted1 = encrypt(&plaintext, &iv1, &key);
        let encrypted2 = encrypt(&plaintext, &iv2, &key);

        // Different IVs should produce different ciphertexts (even with same plaintext)
        assert_ne!(
            encrypted1.ciphertext.as_slice(),
            encrypted2.ciphertext.as_slice()
        );

        // But both should decrypt to the same plaintext
        let decrypted1 = decrypt(&encrypted1, &key);
        let decrypted2 = decrypt(&encrypted2, &key);

        assert_eq!(decrypted1.as_slice(), plaintext.as_slice());
        assert_eq!(decrypted2.as_slice(), plaintext.as_slice());
    }

    #[test]
    fn test_encrypt_decrypt_deterministic_with_same_inputs() {
        // Test that encryption is deterministic: same inputs produce same outputs
        let key = Aes128Key::new_random();
        let iv = Iv::new_unchecked([0u8; 16]);
        let plaintext = AesBlocks::new(vec![0u8; 32]).unwrap();

        let encrypted1 = encrypt(&plaintext, &iv, &key);
        let encrypted2 = encrypt(&plaintext, &iv, &key);

        // Same inputs should produce same ciphertext
        assert_eq!(encrypted1.iv.get(), encrypted2.iv.get());
        assert_eq!(
            encrypted1.ciphertext.as_slice(),
            encrypted2.ciphertext.as_slice()
        );
    }

    #[test]
    fn test_xor_blocks() {
        let block1 = [0xFFu8; 16];
        let block2 = [0x00u8; 16];
        let result = xor_blocks(&block1, &block2);
        assert_eq!(result, [0xFFu8; 16]);

        let block1 = [0xAAu8; 16];
        let block2 = [0x55u8; 16];
        let result = xor_blocks(&block1, &block2);
        assert_eq!(result, [0xFFu8; 16]);

        let block1 = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let block2 = [
            0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02,
            0x01, 0x00,
        ];
        let result = xor_blocks(&block1, &block2);
        assert_eq!(
            result,
            [
                0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f,
                0x0f, 0x0f
            ]
        );
    }

    #[test]
    fn test_encrypt_preserves_iv() {
        let key = Aes128Key::new_random();
        let iv = Iv::new_unchecked([0x42u8; 16]);
        let plaintext = AesBlocks::new(vec![0u8; 32]).unwrap();

        let encrypted = encrypt(&plaintext, &iv, &key);

        // IV should be preserved in the encrypted structure
        assert_eq!(encrypted.iv.get(), iv.get());
    }

    #[test]
    fn test_cbc_encryption_chaining() {
        // Test that CBC mode properly chains blocks
        // If we encrypt two identical blocks, they should produce different ciphertexts
        let key = Aes128Key::new_random();
        let iv = Iv::new_random();

        // Create plaintext with two identical blocks
        let mut plaintext_bytes = vec![0x42u8; 16];
        plaintext_bytes.extend_from_slice(&[0x42u8; 16]);
        let plaintext = AesBlocks::new(plaintext_bytes).unwrap();

        let encrypted = encrypt(&plaintext, &iv, &key);

        // Extract the two ciphertext blocks
        let blocks: Vec<_> = encrypted.ciphertext.iter_blocks().collect();
        assert_eq!(blocks.len(), 2);

        // In CBC mode, identical plaintext blocks should produce different ciphertext blocks
        // (unless the first block XORed with IV equals the second block XORed with first ciphertext)
        // In general, with random IV, they should be different
        assert_ne!(blocks[0], blocks[1]);
    }
}
