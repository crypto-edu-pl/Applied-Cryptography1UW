use super::public_key::PublicKey;
use super::utils::{crt_three, integer_cube_root};
use num_bigint::BigUint;

/// E=3 RSA Broadcast Attack
///
/// When the same plaintext is encrypted with e=3 under three different
/// public keys (with coprime moduli), an attacker can recover the plaintext
/// using the Chinese Remainder Theorem.
///
/// The attack works because:
/// - c_0 = m^3 mod n_0
/// - c_1 = m^3 mod n_1
/// - c_2 = m^3 mod n_2
///
/// Using CRT, we find m^3 mod (n_0 * n_1 * n_2).
/// Since m < n_i for all i, we have m^3 < n_0 * n_1 * n_2,
/// so the CRT result equals m^3 exactly (no reduction happened).
/// Taking the integer cube root gives us m.
pub fn broadcast_attack(
    c0: &BigUint,
    pk0: &PublicKey,
    c1: &BigUint,
    pk1: &PublicKey,
    c2: &BigUint,
    pk2: &PublicKey,
) -> BigUint {
    assert!(
        pk0.e() == &BigUint::from(3u32)
            && pk1.e() == &BigUint::from(3u32)
            && pk2.e() == &BigUint::from(3u32),
        "Broadcast attack requires e=3 for all public keys"
    );

    // Use CRT to find m^3 mod (n_0 * n_1 * n_2)
    // Since m < n_i, we have m^3 < n_0 * n_1 * n_2, so CRT gives exact m^3
    let m_cubed = crt_three(c0, pk0.n(), c1, pk1.n(), c2, pk2.n());

    // Take cube root to recover m
    integer_cube_root(&m_cubed)
}

/// Broadcast attack that returns the decrypted message as a string
pub fn broadcast_attack_string(
    c0: &BigUint,
    pk0: &PublicKey,
    c1: &BigUint,
    pk1: &PublicKey,
    c2: &BigUint,
    pk2: &PublicKey,
) -> Result<String, std::string::FromUtf8Error> {
    let m = broadcast_attack(c0, pk0, c1, pk1, c2, pk2);
    let bytes = m.to_bytes_be();
    String::from_utf8(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rsa::KeyPair;
    use rand::thread_rng;

    #[test]
    fn test_broadcast_attack_small() {
        let mut rng = thread_rng();

        // Generate three different keypairs with e=3
        let kp0 = KeyPair::generate(&mut rng, 512);
        let kp1 = KeyPair::generate(&mut rng, 512);
        let kp2 = KeyPair::generate(&mut rng, 512);

        // The secret message
        let m = BigUint::from(42u32);

        // Encrypt the same message under all three public keys
        let c0 = kp0.public_key().encrypt(&m);
        let c1 = kp1.public_key().encrypt(&m);
        let c2 = kp2.public_key().encrypt(&m);

        // Attacker only has ciphertexts and public keys
        let recovered = broadcast_attack(
            &c0,
            kp0.public_key(),
            &c1,
            kp1.public_key(),
            &c2,
            kp2.public_key(),
        );

        assert_eq!(recovered, m, "Broadcast attack failed to recover message");
    }

    #[test]
    fn test_broadcast_attack_string() {
        let mut rng = thread_rng();

        let kp0 = KeyPair::generate(&mut rng, 512);
        let kp1 = KeyPair::generate(&mut rng, 512);
        let kp2 = KeyPair::generate(&mut rng, 512);

        let message = "secret!";
        let c0 = kp0.public_key().encrypt_string(message);
        let c1 = kp1.public_key().encrypt_string(message);
        let c2 = kp2.public_key().encrypt_string(message);

        let recovered = broadcast_attack_string(
            &c0,
            kp0.public_key(),
            &c1,
            kp1.public_key(),
            &c2,
            kp2.public_key(),
        )
        .unwrap();

        assert_eq!(recovered, message);
    }
}
