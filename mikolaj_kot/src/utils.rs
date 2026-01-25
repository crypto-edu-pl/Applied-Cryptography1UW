use anyhow::{Context, Result};
use base64::{engine::general_purpose, Engine as _};
use clap::{ValueEnum};
use num_bigint::{BigUint, BigInt, ToBigInt, };
use num_traits::{ One, Zero};
use rand_chacha::ChaCha20Rng;
use rand::{RngCore, SeedableRng};

static BASE64_CHARS: [u8; 64] = [
    // 0-15
    b'A', b'B', b'C', b'D', b'E', b'F', b'G', b'H',
    b'I', b'J', b'K', b'L', b'M', b'N', b'O', b'P',
    // 16-31
    b'Q', b'R', b'S', b'T', b'U', b'V', b'W', b'X',
    b'Y', b'Z', b'a', b'b', b'c', b'd', b'e', b'f',
    // 32-47
    b'g', b'h', b'i', b'j', b'k', b'l', b'm', b'n',
    b'o', b'p', b'q', b'r', b's', b't', b'u', b'v',
    // 48-63
    b'w', b'x', b'y', b'z', b'0', b'1', b'2', b'3',
    b'4', b'5', b'6', b'7', b'8', b'9', b'+', b'/',
];

static CHAR_FREQS: [f32; 26] = [
/*a*/   8.167, 1.492, 2.782, 4.253, 12.702, 2.228, 2.015,  // a-g
/*h*/   6.094, 6.966, 0.153, 0.772, 4.025, 2.406, 6.749,   // h-n
/*o*/   7.507, 1.929, 0.095, 5.987, 6.327, 9.056, 2.758,   // o-u
/*v*/   0.978, 2.360, 0.150, 1.974, 0.074                  // v-z
];

const PENALTY: f64 = 10.0;
const SPACE_SCORE: f64 = 10.0;

#[derive(Debug)]
pub struct ConversionError;

pub fn hex_to_base64(m: &str) -> Result<String, ConversionError> {
    let mut res = String::new();
    let mut bytes_iter = m.trim().bytes().peekable();

    // Anonymous function
    let to_hex = |b: u8| (b as char).to_digit(16).ok_or(ConversionError);

    while bytes_iter.peek().is_some() {
        let a_bits = to_hex(bytes_iter.next().unwrap())?;

        let Some(b_byte) = bytes_iter.next() else {
            res.push(BASE64_CHARS[(a_bits << 2) as usize] as char);
            break;
        };
        let b_bits = to_hex(b_byte)?;

        res.push(BASE64_CHARS[((a_bits << 2) | (b_bits >> 2)) as usize] as char);

        let Some(c_byte) = bytes_iter.next() else {
            res.push(BASE64_CHARS[((b_bits & 0b11) << 4) as usize] as char);
            break;
        };
        let c_bits = to_hex(c_byte)?;

        res.push(BASE64_CHARS[(((b_bits & 0b11) << 4) | (c_bits)) as usize] as char);
    }

    Ok(res)
}

pub fn transpose_bytes(bytes: &[u8], keysize: usize) -> Vec<Vec<u8>> {
    (0..keysize)
        .map(|i| {
            bytes.iter()
                .skip(i)
                .step_by(keysize)
                .copied()
                .collect()
        })
        .collect()
}

pub fn score_english_text(bytes: &[u8]) -> f64 {
    let mut score: f64 = 0.0;

    for &byte in bytes.iter() {
        let lower = byte.to_ascii_lowercase();

        match lower {
            b'a'..=b'z' => {
                let index = (lower - b'a') as usize;
                score += CHAR_FREQS[index] as f64;
            },
            b' ' => {
                score += SPACE_SCORE;
            },
            // Common punctuation
            b',' | b'.' | b';' | b':' | b'\'' | b'"' | b'!' | b'?' | b'-' => {
                score += 0.0;
            },
            // Numbers
            b'0'..=b'9' => {
                score += 0.0;
            }
            // Others
            _ => {
                score -= PENALTY;
            },
        }
    }

    score
}

pub fn hamming_distance(bytes_1: &[u8], bytes_2: &[u8]) -> u32 {
    bytes_1.iter()
        .zip(bytes_2)
        .map(|(b1, b2)| (b1 ^ b2).count_ones())
        .sum()
}

// Converts a 20-byte SHA-1 digest into its corresponding five 32-bit registers
pub fn get_registers(digest: &[u8; 20]) -> [u32; 5] {
    let mut h = [0u32; 5];
    for (i, chunk) in digest.chunks(4).enumerate() {
        h[i] = u32::from_be_bytes(chunk.try_into().unwrap());
    }

    h
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum Format { Utf8, Hex, Base64, }

// Parses input string based on the specified format
pub fn parse_input(input: &str, format: Format) -> Result<Vec<u8>> {
    match format {
        Format::Utf8 => Ok(input.as_bytes().to_vec()),
        Format::Hex => hex::decode(input).context("Failed to decode Hex"),
        Format::Base64 => general_purpose::STANDARD
                .decode(input)
                .context("Failed to decode Base64"),
    }
}

// Computes (base^exponent) mod modulus using modular exponentiation
pub fn modpow(base: u32, exponent: u32, modulus: u32) -> u32 {
    if modulus == 1 {
        return 0;
    }
    let mut result = 1u32;
    let mut base = base % modulus;
    let mut exp = exponent;

    while exp > 0 {
        if exp % 2 == 1 {
            result = (result * base) % modulus;
        }
        exp = exp >> 1;
        base = (base * base) % modulus;
    }
    result
}

// Computes the greatest common divisor (GCD) of two BigUint numbers
pub fn gcd(a: &mut BigUint, b: &mut BigUint) -> BigUint {
    while !b.is_zero() {
        *a %= &*b;
        std::mem::swap(a, b);
    }
    a.clone() 
}

// Extended Euclidean Algorithm to find modular inverse
pub fn invmod(e: &BigUint, n: &BigUint) -> BigUint {
    // Placeholder for modular inverse logic
    let mut a = e.to_bigint().unwrap();
    let mut m = n.to_bigint().unwrap();
    let m0 = m.clone();
    let mut y = BigInt::zero();
    let mut x = BigInt::one();

    // If m == 1, return 0
    if m == BigInt::one() {
        return BigUint::from(0u32);
    }

    // Apply Extended Euclidean Algorithm
    while a > BigInt::one() {
        let q = &a / &m;
        let mut t = m.clone();

        m = &a % &m;
        a = t;
        t = y.clone();

        y = &x - &q * &y;
        x = t;
    }
    
    // Make x positive
    if x < BigInt::zero() {
        x += &m0;
    }

    // Convert back to BigUint
    x.to_biguint().unwrap()
}

// Miller-Rabin primality test
pub fn is_prime(n: &BigUint, k: usize) -> bool {
    if *n <= BigUint::from(1u32) { return false; }
    if *n <= BigUint::from(3u32) { return true; }
    if n % 2u32 == BigUint::zero() { return false; }

    // Write n-1 as 2^r * d
    let n_minus_1 = n - 1u32;
    let mut d = n_minus_1.clone();
    let mut r = 0;
    while &d % 2u32 == BigUint::zero() {
        d /= 2u32;
        r += 1;
    }

    for _ in 0..k {
        // Choose a random witness 'a' in [2, n-2]
        let a = BigUint::from(2u32); 
        let mut x = a.modpow(&d, n);

        if x == BigUint::one() || x == n_minus_1 {
            continue;
        }

        // Repeat r-1 times
        let mut composite = true;
        for _ in 0..r - 1 {
            x = x.modpow(&BigUint::from(2u32), n);
            if x == n_minus_1 {
                composite = false;
                break;
            }
        }
        if composite { return false; }
    }
    true
}

// Generates a large prime number with the specified bit length
pub fn generate_large_prime(bits: usize) -> BigUint {
    let mut rng = ChaCha20Rng::from_entropy();
    let mut bytes = vec![0u8; bits / 8];
    
    // Generate random odd numbers until a prime is found
    loop {
        rng.fill_bytes(&mut bytes);
        // Ensure it's the right length and odd
        bytes[0] |= 0b1000_0000;
        bytes[(bits / 8) - 1] |= 0b0000_0001;
        
        let p = BigUint::from_bytes_be(&bytes);
        if is_prime(&p, 10) {
            return p;
        }
    }
}

pub fn cube_root(n: &BigUint) -> BigUint {
    let mut low = BigUint::zero();
    let mut high = n.clone();
    
    // Simple inary search for cube root
    while low <= high {
        let mid = (&low + &high) / 2u32;
        let mid_cubed = mid.pow(3);
        
        // Check if mid^3 is equal to, less than, or greater than n
        if mid_cubed == *n {
            return mid;
        } else if mid_cubed < *n {
            low = mid + 1u32;
        } else {
            high = mid - 1u32;
        }
    }
    high
}