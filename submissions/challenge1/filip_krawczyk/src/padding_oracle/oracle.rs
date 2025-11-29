use crate::{
    aes::Aes128Key,
    cbc::{CbcEncryptedBlocks, Iv, decrypt, encrypt},
    pkcs7::{pad, unpad},
};

pub struct PaddingOracle {
    key: Aes128Key,
    verbose: bool,
}

impl PaddingOracle {
    pub fn new(verbose: bool) -> Self {
        let key = Aes128Key::new_random();
        Self { key, verbose }
    }

    pub fn get_encrypted_message(&self) -> CbcEncryptedBlocks {
        // This message is private and never exposed unencrypted.
        let plaintext = "Hello, world! This is quite a long message, isn't it?";
        let padded = pad::<16>(plaintext.as_bytes());
        if self.verbose {
            println!("[PaddingOracle] Padded plaintext: {padded:?}");
        }
        let iv = Iv::new_random();
        let encrypted = encrypt(&padded, &iv, &self.key);
        if self.verbose {
            println!("[PaddingOracle] Encrypted: {encrypted:?}");
        }
        encrypted
    }

    pub fn is_padding_valid(&self, ciphertext: &CbcEncryptedBlocks) -> bool {
        if self.verbose {
            // println!("[PaddingOracle] Checking padding validity for ciphertext: {ciphertext:?}");
        }
        let plaintext = decrypt(ciphertext, &self.key);
        if self.verbose {
            println!("[PaddingOracle] Decrypted to: {plaintext:?}");
        }
        unpad(&plaintext).is_ok()
    }
}
