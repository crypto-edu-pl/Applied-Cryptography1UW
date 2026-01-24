use challenge2::diffie_hellman;
use rand::thread_rng;

fn main() {
    println!("=== Diffie-Hellman Key Exchange (NIST 1536-bit) ===\n");
    let mut rng = thread_rng();

    let config = diffie_hellman::Config::nist_1536();
    println!("p = {} bits", config.p().bits());
    println!("g = {}\n", config.g());

    let alice = diffie_hellman::Party::new(&config, &mut rng);
    println!("Alice: {:?}", alice);

    let bob = diffie_hellman::Party::new(&config, &mut rng);
    println!("Bob: {:?}", bob);

    let alice_message = alice.generate_message();
    let bob_message = bob.generate_message();

    let s_alice = alice.compute_shared_secret(&bob_message);
    let s_bob = bob.compute_shared_secret(&alice_message);

    assert_eq!(s_alice, s_bob, "Shared secrets don't match!");
    println!("\n✓ Shared secrets match!");
    println!("Shared secret: {} bits", s_alice.bits());

    let key = diffie_hellman::utils::derive_key(&s_alice);
    println!("Derived key (SHA-256): {}", hex::encode(&key));

    let (enc_key, mac_key) = key.split_at(16);
    println!("\nEncryption key (128 bits): {}", hex::encode(enc_key));
    println!("MAC key (128 bits):        {}", hex::encode(mac_key));
}
