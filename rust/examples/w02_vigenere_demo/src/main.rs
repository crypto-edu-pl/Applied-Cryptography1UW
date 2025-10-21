// vigenere.rs
// Simple Vigenère cipher in Rust — encrypt and decrypt A–Z plaintext.

use std::io::{self, Write};

fn main() {
    println!("=== Vigenère Cipher ===");
    print!("Enter plaintext (A–Z letters only): ");
    io::stdout().flush().unwrap();

    let mut plaintext = String::new();
    io::stdin().read_line(&mut plaintext).unwrap();

    print!("Enter key (A–Z letters only): ");
    io::stdout().flush().unwrap();

    let mut key = String::new();
    io::stdin().read_line(&mut key).unwrap();

    let plaintext = clean(&plaintext);
    let key = clean(&key);

    if plaintext.is_empty() || key.is_empty() {
        eprintln!("Error: plaintext or key is empty.");
        return;
    }

    let ciphertext = vigenere_encrypt(&plaintext, &key);
    println!("\nCiphertext: {}", ciphertext);

    let decrypted = vigenere_decrypt(&ciphertext, &key);
    println!("Decrypted : {}", decrypted);
}

/// Keep only uppercase A–Z
fn clean(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_alphabetic())
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

/// Encrypt plaintext with key (A–Z only)
fn vigenere_encrypt(plain: &str, key: &str) -> String {
    let mut out = String::with_capacity(plain.len());
    let kb = key.as_bytes();
    let klen = kb.len();

    for (i, &c) in plain.as_bytes().iter().enumerate() {
        if c >= b'A' && c <= b'Z' {
            let p = c - b'A';
            let k = kb[i % klen] - b'A';
            let enc = (p + k) % 26;
            out.push((b'A' + enc) as char);
        }
    }
    out
}

/// Decrypt ciphertext with key (A–Z only)
fn vigenere_decrypt(cipher: &str, key: &str) -> String {
    let mut out = String::with_capacity(cipher.len());
    let kb = key.as_bytes();
    let klen = kb.len();

    for (i, &c) in cipher.as_bytes().iter().enumerate() {
        if c >= b'A' && c <= b'Z' {
            let ct = c - b'A';
            let k = kb[i % klen] - b'A';
            let dec = (26 + ct - k) % 26;
            out.push((b'A' + dec) as char);
        }
    }
    out
}
