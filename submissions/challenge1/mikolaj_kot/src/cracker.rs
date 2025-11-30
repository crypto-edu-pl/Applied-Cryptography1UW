use crate::utils::{ hamming_distance, score_english_text, transpose_bytes, };
use crate::crypto::{ repeating_xor };
use std::cmp::min;

const MAX_KEY_SIZE: usize = 40;

pub struct CrackResult {
    pub key: Vec<u8>,
    pub plaintext: Vec<u8>,
    pub score: f64,
}

#[derive(Copy, Clone, Debug)]
pub enum Cracker {
    SingleByteXor,
    RepeatingKeyXor,
}

impl Cracker {
    pub fn crack(&self, ciphertext: &[u8], num_of_results: usize) -> Vec<CrackResult> {
        let results: Vec<CrackResult> = match self {
            Self::SingleByteXor => self.solve_single_byte(ciphertext, num_of_results),
            Self::RepeatingKeyXor => self.solve_repeating(ciphertext, num_of_results),
        };

        results
    }

    pub fn print_results(&self, results: Vec<CrackResult>) {
        println!("--- TOP {} CANDIDATES ---", results.len());
        for result in results {
            println!("Key: {:?} | Message: {}\n | Score: {:.2}", 
                result.key, String::from_utf8_lossy(&result.plaintext), result.score);
        };
    }

    fn solve_single_byte(&self, ciphertext: &[u8], num_of_results: usize) -> Vec<CrackResult> {
        let mut results: Vec<CrackResult> = Vec::new();

        for key in u8::MIN..=u8::MAX {
            let decrypted_bytes: Vec<u8> = ciphertext.iter().map(|&b| b ^ key).collect();                
            let score = score_english_text(&decrypted_bytes);
            results.push(CrackResult { key: vec![key], plaintext: decrypted_bytes, score });
        }

        results.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap());

        results.into_iter().take(num_of_results as usize).collect()
    }

    fn solve_repeating(&self, ciphertext: &[u8], num_of_results: usize) -> Vec<CrackResult> {
        let mut results: Vec<CrackResult> = Vec::new();

        let mut distances: Vec<(usize, f32)> = Vec::with_capacity(MAX_KEY_SIZE - 2);

        for keysize in 2..min(MAX_KEY_SIZE, ciphertext.len() / 4) {
            let block1 = &ciphertext[0..keysize];
            let block2 = &ciphertext[keysize..keysize * 2];
            let block3 = &ciphertext[keysize * 2..keysize * 3];
            let block4 = &ciphertext[keysize * 3..keysize * 4];

            let d12 = hamming_distance(block1, block2);
            let d13 = hamming_distance(block1, block3);
            let d14 = hamming_distance(block1, block4);
            let d23 = hamming_distance(block2, block3);
            let d24 = hamming_distance(block2, block4);
            let d34 = hamming_distance(block3, block4);
            
            let total_dist = d12 + d13 + d14 + d23 + d24 + d34;
            let normalised = (total_dist as f32 / 6.0) / keysize as f32;

            distances.push((keysize, normalised));
        }

        distances.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap());

        for (keysize, _dist) in distances.iter().take(num_of_results) {
            let mut key_candidate: Vec<u8> = Vec::with_capacity(*keysize);
            
            let transposed_blocks = transpose_bytes(ciphertext, *keysize);
            for block in transposed_blocks {
                let byte = self.solve_single_byte(&block, 1)[0].key[0];
                key_candidate.push(byte);
            }
            
            let cracked_plaintext = repeating_xor(ciphertext, &key_candidate);
            let score = score_english_text(&cracked_plaintext);
            results.push(CrackResult {
                key: (key_candidate),
                plaintext: (cracked_plaintext),
                score,
            })
        }

        results.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap());

        results
    }
}