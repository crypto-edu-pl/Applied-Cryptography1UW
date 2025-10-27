use std::time::{SystemTime, UNIX_EPOCH};

/// BAD: 32-bit LCG with parameters from Numerical Recipes.
/// State is only 32 bits and equals the last output; trivially predictable.
struct Lcg32 {
    state: u32,
}

impl Lcg32 {
    fn seeded_from_time() -> Self {
        // BAD: seeding from time has very low entropy (guessable within seconds)
        let secs = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        Self { state: (secs as u32) ^ 0x9E3779B9 } // arbitrary xor to "mix" (still bad)
    }

    fn next_u32(&mut self) -> u32 {
        // x_{n+1} = (a*x_n + c) mod 2^32
        const A: u32 = 1664525;
        const C: u32 = 1013904223;
        self.state = self.state.wrapping_mul(A).wrapping_add(C);
        self.state
    }

    /// BAD PRG output: just dump bytes of the state repeatedly.
    fn generate(&mut self, len: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(len);
        while out.len() < len {
            let x = self.next_u32();
            out.extend_from_slice(&x.to_le_bytes());
        }
        out.truncate(len);
        out
    }
}

fn main() {
    // Demonstrate predictability
    let mut prg = Lcg32::seeded_from_time();
    let first = prg.next_u32();
    let second = prg.next_u32();

    println!("First  u32: {:#010x}", first);
    println!("Second u32: {:#010x}", second);

    // An attacker who sees `first` knows the internal state at step 1,
    // so they can compute `second`, `third`, ... exactly. No secrecy.
    let mut attacker = Lcg32 { state: first };
    let attacker_second = attacker.next_u32();
    println!("Attacker predicts second: {:#010x} (matches)", attacker_second);
}
