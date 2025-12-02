use aes::cipher::{BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};

type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;

const BLOCK_SIZE: usize = 16;

pub struct Oracle {
    key: [u8; BLOCK_SIZE],
    iv: [u8; BLOCK_SIZE],
    secret: Box<str>,
}

impl Oracle {
    pub fn new(key: [u8; BLOCK_SIZE], iv: [u8; BLOCK_SIZE], secret: &str) -> Self {
        Self {
            key,
            iv,
            secret: secret.into(),
        }
    }

    pub fn encrypt(&mut self, msg: &str) -> Box<[u8]> {
        let plaintext = format!("{msg}{}", self.secret);
        let encrypted_len = (plaintext.len() + 1).div_ceil(BLOCK_SIZE) * BLOCK_SIZE;

        let mut buf = vec![0_u8; encrypted_len];

        let pt_len = plaintext.len();
        buf[..pt_len].copy_from_slice(plaintext.as_bytes());
        let ciphertext = Aes128CbcEnc::new(&self.key.into(), &self.iv.into())
            .encrypt_padded_mut::<Pkcs7>(&mut buf, pt_len)
            .unwrap();

        let last_block = ciphertext.last_chunk::<16>().unwrap();
        self.iv = *last_block;

        ciphertext.into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_predicable_iv() {
        let key = [97_u8; 16];
        let iv = [97_u8; 16];

        let part1_plaintext = "js93id03ig85hanf";
        let part2_plaintext = "j2t[3-=2a9-32hjo";
        let part1_padding = String::from_utf8(vec![16_u8; 16]).unwrap();

        let mut oracle = Oracle::new(key, iv, "");
        let part1_ciphertext = oracle.encrypt(part1_plaintext);
        let part2_ciphertext = oracle.encrypt(part2_plaintext);

        let merged_plaintext = format!("{part1_plaintext}{part1_padding}{part2_plaintext}");

        let mut oracle = Oracle::new(key, iv, "");
        let merged_ciphertext = oracle.encrypt(&merged_plaintext);

        assert_eq!(
            part1_ciphertext.len() + part2_ciphertext.len(),
            merged_ciphertext.len()
        );
        assert_eq!(
            merged_ciphertext[..(part1_ciphertext.len())],
            *part1_ciphertext
        );
        assert_eq!(
            merged_ciphertext[(part1_ciphertext.len())..],
            *part2_ciphertext
        );
    }
}
