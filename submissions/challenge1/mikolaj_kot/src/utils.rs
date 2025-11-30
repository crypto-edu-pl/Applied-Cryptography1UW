use anyhow::{Context, Result};
use base64::{engine::general_purpose, Engine as _};
use clap::{ValueEnum};

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

pub fn get_registers(digest: &[u8; 20]) -> [u32; 5] {
    let mut h = [0u32; 5];
    for (i, chunk) in digest.chunks(4).enumerate() {
        h[i] = u32::from_be_bytes(chunk.try_into().unwrap());
    }

    h
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum Format { Utf8, Hex, Base64, }

pub fn parse_input(input: &str, format: Format) -> Result<Vec<u8>> {
    match format {
        Format::Utf8 => Ok(input.as_bytes().to_vec()),
        Format::Hex => hex::decode(input).context("Failed to decode Hex"),
        Format::Base64 => general_purpose::STANDARD
                .decode(input)
                .context("Failed to decode Base64"),
    }
}