use rand::RngCore;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

/// A secure PRG: expand a 256-bit seed into `len` bytes using ChaCha20Rng.
fn prg_chacha20(seed: [u8; 32], len: usize) -> Vec<u8> {
    // Construct from a fixed-length seed (e.g., shared secret from KDF)
    let mut rng = ChaCha20Rng::from_seed(seed);
    let mut out = vec![0u8; len];
    rng.fill_bytes(&mut out);
    out
}

fn main() {
    // In practice, get the seed from a KDF or OsRng; here we demo OsRng → 32 bytes
    let mut seed = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut seed);

    // If you want deterministic output for testing, replace above two lines with:
    // let seed: [u8;32] = [0u8;32]; // or fill from hex::decode(...).unwrap().try_into().unwrap();

    let keystream = prg_chacha20(seed, 64); // 64 bytes of pseudorandom output

    println!("Seed (hex): {}", hex::encode(seed));
    println!("Keystream (hex): {}", hex::encode(keystream));
}
