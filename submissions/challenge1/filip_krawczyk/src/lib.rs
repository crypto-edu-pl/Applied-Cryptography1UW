// use crate::{
//     aes::Aes128Key,
//     cbc::{decrypt, encrypt},
// };

pub mod aes;
pub mod bit_flipping;
pub mod blocks;
pub mod cbc;
pub mod pkcs7;

// fn main() {
//     let plaintext = "Hello, world! This block is much looooonger";
//     let plaintext_padded = pkcs7::pad::<16>(plaintext.as_bytes());
//     let key = Aes128Key::new_random();
//     let ciphertext = encrypt(&plaintext_padded, &[0_u8; 16], &key);

//     let decrypted1 = decrypt(&ciphertext.0, &[0_u8; 16], &key);
//     let decrypted2 = decrypt(
//         &ciphertext.0,
//         &[1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
//         &key,
//     );

//     println!("Ciphertext: {:?}", ciphertext.0);
//     println!("Decrypted1: {decrypted1:?}");
//     println!("Decrypted2: {decrypted2:?}");
// }
