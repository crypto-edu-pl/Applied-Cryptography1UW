use crate::{
    aes::Aes128Key,
    bit_flipping::cookie::{ParseCookieError, encode_userdata, parse_cookie},
    cbc::{CbcEncryptedBlocks, Iv, decrypt, encrypt},
    pkcs7::{Pkcs7PaddingError, pad, unpad},
};

pub struct Server {
    key: Aes128Key,
}

impl Default for Server {
    fn default() -> Self {
        Self::new()
    }
}

impl Server {
    pub fn new() -> Self {
        Self {
            key: Aes128Key::new_random(),
        }
    }

    pub fn get_encrypted_cookie_for_user(&self, userdata: &str) -> CbcEncryptedBlocks {
        let cookie = encode_userdata(userdata);
        let padded = pad::<16>(cookie.as_bytes());
        let iv = Iv::new_random();
        encrypt(&padded, &iv, &self.key)
    }

    pub fn is_admin(&self, cookie: &CbcEncryptedBlocks) -> Result<bool, MessageDecodingError> {
        let plaintext = decrypt(cookie, &self.key);
        let unpadded = unpad(&plaintext)?;
        let utf8 = String::from_utf8(unpadded).map_err(|_| MessageDecodingError::InvalidUtf8)?;
        let values = parse_cookie(&utf8)?;
        let is_admin = values.get("admin").map(|v| v == "true").unwrap_or(false);
        Ok(is_admin)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum MessageDecodingError {
    #[error("Invalid UTF-8")]
    InvalidUtf8,

    #[error(transparent)]
    Pkcs7PaddingError(#[from] Pkcs7PaddingError),

    #[error(transparent)]
    ParseCookieError(#[from] ParseCookieError),
}
