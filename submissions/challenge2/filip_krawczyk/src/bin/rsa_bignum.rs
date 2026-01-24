use challenge2::rsa;
use num_bigint::BigUint;
use rand::thread_rng;

fn main() {
    println!("=== RSA with Big Primes (1024-bit) ===\n");

    let mut rng = thread_rng();

    // Generate keypair with 1024-bit primes (resulting in ~2048-bit modulus)
    println!("Generating RSA keypair with 1024-bit primes...");
    let keypair = rsa::KeyPair::generate(&mut rng, 1024);
    println!("Generated keypair: {:?}", keypair);
    println!("Modulus n has {} bits", keypair.public_key().n().bits());

    println!("\n--- Encrypting number 42 ---");
    let m = BigUint::from(42u32);
    println!("Original message: m = {}", m);

    let c = keypair.public_key().encrypt(&m);
    println!("Ciphertext: c = {} ({} bits)", c, c.bits());

    let decrypted = keypair.decrypt(&c);
    println!("Decrypted: m = {}", decrypted);

    assert_eq!(m, decrypted, "Decryption failed!");
    println!("\n✓ Encryption/Decryption of number successful!");

    println!("\n--- Encrypting string 'Hello, RSA!' ---");
    let message = "Hello, RSA!";
    println!("Original message: \"{}\"", message);
    println!("As hex: 0x{}", hex::encode(message.as_bytes()));

    let c = keypair.public_key().encrypt_string(message);
    println!("Ciphertext: {} ({} bits)", c, c.bits());

    let decrypted_str = keypair
        .decrypt_to_string(&c)
        .expect("Failed to decrypt to string");
    println!("Decrypted: \"{}\"", decrypted_str);

    assert_eq!(message, decrypted_str, "String decryption failed!");
    println!("\n✓ String encryption/decryption successful!");

    println!("\n--- Encrypting longer message ---");
    let long_message = "The quick brown fox jumps over the lazy dog.";
    println!("Original: \"{}\"", long_message);

    let c = keypair.public_key().encrypt_string(long_message);
    let decrypted_long = keypair.decrypt_to_string(&c).expect("Failed to decrypt");
    println!("Decrypted: \"{}\"", decrypted_long);

    assert_eq!(long_message, decrypted_long);
    println!("\n✓ Long message encryption/decryption successful!");
}
