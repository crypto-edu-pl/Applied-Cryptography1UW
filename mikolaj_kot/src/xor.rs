use anyhow::{Result, bail};
use clap::{ValueEnum};

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum XorType {
    Single,
    Fixed,
    Repeating,
    Otp,
}

pub fn single_xor(c_bytes: &[u8], k: u8) -> Vec<u8> {
    c_bytes.iter().map(|&b| b ^ k).collect()
}

pub fn fixed_xor(c_bytes: &[u8], k_bytes: &[u8]) -> Result<Vec<u8>> {
    if c_bytes.len() != k_bytes.len() {
        bail!("Fixed XOR requires buffers of equal length")
    }
    Ok(c_bytes.iter().zip(k_bytes).map(|(&b, &k)| b ^ k).collect())
}

pub fn otp(c_bytes: &[u8], k_bytes: &[u8]) -> Result<Vec<u8>> {
    if c_bytes.len() > k_bytes.len() {
        bail!("OTP Error: Key is shorter than message. Insecure.")
    }
    Ok(c_bytes.iter().zip(k_bytes).map(|(&b, &k)| b ^ k).collect())
}

pub fn repeating_xor(c_bytes: &[u8], k_bytes: &[u8]) -> Vec<u8> {
    c_bytes.iter().zip(k_bytes.iter().cycle()).map(|(b, k)| b ^ k).collect()
}

pub fn secret_prefix_mac(key: &[u8], message: &[u8]) -> [u8; 20] {
    let mut input = Vec::with_capacity(key.len() + message.len());
    input.extend_from_slice(key);
    input.extend_from_slice(message);

    sha1(&input)
}

pub fn verify_mac(key: &[u8], message: &[u8], provided_mac: &[u8; 20]) -> bool {
    let calculated_mac = secret_prefix_mac(key, message);

    // INSECURE: In production, use constant time compariosn
    calculated_mac == *provided_mac
}

pub fn sha1_modified(message: &[u8], registers: &[u32; 5], total_bytes_processed: u64) -> [u8; 20] {
    let mut buffer = message.to_vec();

    // Initialise variables:
    let mut h: [u32; 5] = registers.clone();
    let ml: u64 = (total_bytes_processed + message.len() as u64) * 8; 

    // Pre-processing
    buffer.push(0x80);
    let rem = buffer.len() % 64;
    let pad_len = if rem <= 56 {
        56 - rem
    } else {
        64 + 56 - rem
    };

    // append pad_len zero bytes
    buffer.extend(std::iter::repeat(0).take(pad_len));
    buffer.extend_from_slice(&ml.to_be_bytes());

    let mut w = [0u32; 80];
    for chunk in buffer.chunks(64) {
        for i in 0..16 {
            let j = i * 4;
            w[i] = (chunk[j] as u32) << 24 | 
                (chunk[j + 1] as u32) << 16 | 
                (chunk[j + 2] as u32) << 8 | 
                (chunk[j + 3] as u32);
        }

        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1); 
        }

        let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
        for i in 0..80 {
            let (f, k) = match i {
                0..20 => { ((b & c) | ((!b) & d), 0x5A827999) },
                20..40 => { (b ^ c ^ d, 0x6ED9EBA1) },
                40..60 => { ((b & c) | (b & d) | (c & d), 0x8F1BBCDC) },
                60..80 => { (b ^ c ^ d, 0xCA62C1D6) },
                _ => unreachable!(),
            };

            let temp = a.rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(w[i]);

            (e, d, c, b, a) = (d, c, b.rotate_left(30), a, temp);
        }

        let t: [u32; 5] = [a, b, c, d, e]; 
        for i in 0..5 {
            h[i] = h[i].wrapping_add(t[i]);
        }

    }

    let mut digest = [0u8; 20];
    for i in 0..5 {
        digest[i * 4..(i + 1) * 4].copy_from_slice(&h[i].to_be_bytes());
    }

    digest
}

pub fn sha1(message: &[u8]) -> [u8; 20] {
    let mut buffer = message.to_vec();

    // Initialise variables:
    let mut h: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
    let ml: u64 = (message.len() as u64) * 8; // message length in bits 

    /*Pre-processing:
    append the bit '1' to the message.
    append 0 ≤ k < 512 bits '0', such that the resulting message length in bits
    is congruent to −64 ≡ 448 (mod 512)
    append ml, the original message length in bits, as a 64-bit big-endian integer.*/
    buffer.push(0x80);
    let rem = buffer.len() % 64;
    let pad_len = if rem <= 56 {
        56 - rem
    } else {
        64 + 56 - rem
    };

    // append pad_len zero bytes
    buffer.extend(std::iter::repeat(0).take(pad_len));
    buffer.extend_from_slice(&ml.to_be_bytes());

    let mut w = [0u32; 80];
    for chunk in buffer.chunks(64) {
        for i in 0..16 {
            let j = i * 4;
            w[i] = (chunk[j] as u32) << 24 | 
                (chunk[j + 1] as u32) << 16 | 
                (chunk[j + 2] as u32) << 8 | 
                (chunk[j + 3] as u32);
        }

        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1); 
        }

        let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
        for i in 0..80 {
            let (f, k) = match i {
                0..20 => { ((b & c) | ((!b) & d), 0x5A827999) },
                20..40 => { (b ^ c ^ d, 0x6ED9EBA1) },
                40..60 => { ((b & c) | (b & d) | (c & d), 0x8F1BBCDC) },
                60..80 => { (b ^ c ^ d, 0xCA62C1D6) },
                _ => unreachable!(),
            };

            let temp = a.rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(w[i]);

            (e, d, c, b, a) = (d, c, b.rotate_left(30), a, temp);
        }

        let t: [u32; 5] = [a, b, c, d, e]; 
        for i in 0..5 {
            h[i] = h[i].wrapping_add(t[i]);
        }

    }

    let mut digest = [0u8; 20];
    for i in 0..5 {
        digest[i * 4..(i + 1) * 4].copy_from_slice(&h[i].to_be_bytes());
    }

    digest
}

pub fn md_padding(message: &[u8]) -> Vec<u8> {
    let mut padding = Vec::new();
    let ml = (message.len() as u64) * 8; 

    // Append the '1' bit (0x80 byte)
    padding.push(0x80);

    // Calculate zero padding
    let current_len = message.len() + 1; 
    let rem = current_len % 64;
    
    let pad_len = if rem <= 56 {
        56 - rem
    } else {
        64 + 56 - rem
    };

    // Append zeros
    padding.extend(std::iter::repeat(0).take(pad_len));

    // Append length (Big Endian)
    padding.extend_from_slice(&ml.to_be_bytes());

    padding
}

#[test]
fn test_md_padding() {
    let msg = b"john frusciante";
    let padding = md_padding(msg);

    assert_eq!(padding[0], 0x80);

    let total_len = msg.len() + padding.len();
    assert_eq!(total_len % 64, 0);
    
    let suffix = &padding[padding.len()-8..];
    let len_val = u64::from_be_bytes(suffix.try_into().unwrap());
    assert_eq!(len_val, 48);
}
