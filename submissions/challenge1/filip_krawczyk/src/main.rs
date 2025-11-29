use crate::{
    aes::{Aes128Key, decrypt_block, encrypt_block},
    blocks::Blocks,
    pkcs7::unpad,
};

pub mod aes;
pub mod blocks;
pub mod pkcs7;

fn main() {
    let plaintext = "Hello, world!";
    let plaintext_padded = pkcs7::pad::<16>(plaintext.as_bytes());
    let key = Aes128Key([0; 16]);
    let ciphertext = encrypt_block(&plaintext_padded.to_vec().try_into().unwrap(), &key);
    let decrypted = decrypt_block(&ciphertext, &key);
    let decrypted_data = unpad::<16>(&Blocks::new(decrypted.to_vec()).unwrap()).unwrap();
    println!("{:?}", String::from_utf8(decrypted_data).unwrap());
}
