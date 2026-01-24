use challenge2::rsa;
use num_bigint::BigUint;

fn main() {
    println!("=== RSA with Small Primes ===\n");

    // Use small primes from a prime table
    // For e=3 to work, we need gcd(3, (p-1)*(q-1)) = 1
    // This means (p-1) and (q-1) must not be divisible by 3
    // p=59: 59-1=58, 58%3=1 ✓
    // q=53: 53-1=52, 52%3=1 ✓
    let p = BigUint::from(59u32);
    let q = BigUint::from(53u32);
    let e = BigUint::from(3u32);

    println!("p = {}", p);
    println!("q = {}", q);
    println!("n = p * q = {}", &p * &q);
    let et = (&p - 1u32) * (&q - 1u32);
    println!("et = (p-1)*(q-1) = {}", et);
    println!("e = {}", e);

    let keypair = rsa::KeyPair::from_primes(p, q, e).expect("Failed to create keypair");
    println!("\nGenerated keypair: {:?}", keypair);
    println!("Public key: {}", keypair.public_key());

    println!("\n--- Encrypting number 42 ---");
    let m = BigUint::from(42u32);
    println!("Original message: m = {}", m);

    let c = keypair.public_key().encrypt(&m);
    println!("Ciphertext: c = m^e mod n = {}", c);

    let decrypted = keypair.decrypt(&c);
    println!("Decrypted: m = c^d mod n = {}", decrypted);

    assert_eq!(m, decrypted, "Decryption failed!");
    println!("\n✓ Encryption/Decryption successful!");

    println!("\n--- Verifying invmod(17, 3120) = 2753 ---");
    let inv = rsa::utils::invmod(&BigUint::from(17u32), &BigUint::from(3120u32)).unwrap();
    println!("invmod(17, 3120) = {}", inv);
    assert_eq!(inv, BigUint::from(2753u32));
    println!("✓ invmod verification passed!");

    println!("\n--- Classic textbook example (p=61, q=53, e=17) ---");
    let p2 = BigUint::from(61u32);
    let q2 = BigUint::from(53u32);
    let e2 = BigUint::from(17u32);
    let keypair2 = rsa::KeyPair::from_primes(p2, q2, e2).expect("Failed to create keypair");

    let m2 = BigUint::from(42u32);
    let c2 = keypair2.public_key().encrypt(&m2);
    let d2 = keypair2.decrypt(&c2);
    println!("m=42 -> c={} -> m={}", c2, d2);
    assert_eq!(m2, d2);
    println!("✓ Textbook example passed!");
}
