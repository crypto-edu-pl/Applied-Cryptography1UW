use challenge2::rsa;
use num_bigint::BigUint;
use rand::thread_rng;

fn main() {
    println!("=== E=3 RSA Broadcast Attack Demo ===\n");

    let mut rng = thread_rng();

    println!("Generating three different RSA keypairs with e=3...\n");
    let kp0 = rsa::KeyPair::generate(&mut rng, 512);
    let kp1 = rsa::KeyPair::generate(&mut rng, 512);
    let kp2 = rsa::KeyPair::generate(&mut rng, 512);

    println!("Public Key 0: {}", kp0.public_key());
    println!("Public Key 1: {}", kp1.public_key());
    println!("Public Key 2: {}", kp2.public_key());

    // The secret message that gets encrypted under all three keys
    let secret = BigUint::from(42u32);
    println!(
        "\n--- Victim encrypts secret message m={} under all three public keys ---",
        secret
    );

    let c0 = kp0.public_key().encrypt(&secret);
    let c1 = kp1.public_key().encrypt(&secret);
    let c2 = kp2.public_key().encrypt(&secret);

    println!("c0 = m^3 mod n0 = {}", c0);
    println!("c1 = m^3 mod n1 = {}", c1);
    println!("c2 = m^3 mod n2 = {}", c2);

    println!("\n--- Attacker captures ciphertexts and public keys ---");
    println!("Attacker has: c0, c1, c2, pk0, pk1, pk2");
    println!("Attacker does NOT have: any private keys");

    println!("\n--- Attacker performs broadcast attack ---");
    println!("1. Use CRT to find m^3 from the three residues");
    println!("2. Take cube root to recover m");

    let recovered = rsa::broadcast_attack(
        &c0,
        kp0.public_key(),
        &c1,
        kp1.public_key(),
        &c2,
        kp2.public_key(),
    );

    println!("\nRecovered message: m = {}", recovered);
    assert_eq!(recovered, secret);
    println!("\n✓ Attack successful! Recovered the secret without any private key!");

    // Now demonstrate with a string message
    println!("\n\n=== String Message Attack ===\n");

    let secret_message = "Attack at dawn!";
    println!("Secret message: \"{}\"", secret_message);
    println!(
        "As bytes (hex): 0x{}",
        hex::encode(secret_message.as_bytes())
    );

    let c0 = kp0.public_key().encrypt_string(secret_message);
    let c1 = kp1.public_key().encrypt_string(secret_message);
    let c2 = kp2.public_key().encrypt_string(secret_message);

    println!("\nEncrypted under three different public keys...");

    let recovered_string = rsa::broadcast_attack::broadcast_attack_string(
        &c0,
        kp0.public_key(),
        &c1,
        kp1.public_key(),
        &c2,
        kp2.public_key(),
    )
    .expect("Failed to decode string");

    println!("Recovered message: \"{}\"", recovered_string);
    assert_eq!(recovered_string, secret_message);
    println!("\n✓ String attack successful!");
}
