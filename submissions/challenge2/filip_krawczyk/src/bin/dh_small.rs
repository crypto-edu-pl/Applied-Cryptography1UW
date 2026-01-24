use challenge2::diffie_hellman;
use rand::thread_rng;

fn main() {
    println!("=== Diffie-Hellman Key Exchange (Small Parameters) ===\n");
    let mut rng = thread_rng();

    let config = diffie_hellman::Config::small();
    println!("p = {}, g = {}\n", config.p(), config.g());

    let alice = diffie_hellman::Party::new(&config, &mut rng);
    println!("Alice: {:?}", alice);

    let bob = diffie_hellman::Party::new(&config, &mut rng);
    println!("Bob: {:?}", bob);

    let alice_message = alice.generate_message();
    let bob_message = bob.generate_message();

    let s_alice = alice.compute_shared_secret(&bob_message);
    let s_bob = bob.compute_shared_secret(&alice_message);

    println!("\nAlice computes: s = B^a mod p = {}", s_alice);
    println!("Bob computes:   s = A^b mod p = {}", s_bob);

    assert_eq!(s_alice, s_bob, "Shared secrets don't match!");
    println!("\n✓ Shared secrets match: {}", s_alice);

    let key = diffie_hellman::utils::derive_key(&s_alice);
    println!("Derived key (SHA-256): {}", hex::encode(&key));

    let (enc_key, mac_key) = key.split_at(16);
    println!("\nEncryption key (128 bits): {}", hex::encode(enc_key));
    println!("MAC key (128 bits):        {}", hex::encode(mac_key));
}
