use crate::utils::hex_to_base64;
use crate::cracker::{ Cracker, CrackResult };
use crate::crypto::{ fixed_xor, md_padding, sha1_modified }; 
use crate::utils::{ get_registers, };
use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;

pub fn run_challenge_1() {
    println!("----- Running Set 1 Challenge 1 Demo -----");
    
    let hex_string = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
    println!("Hex: {}", hex_string);

    let base64 = hex_to_base64(&hex_string);

    match base64 {
        Ok(base64) =>  {
            println!("Base64: {}", base64);
            if base64 == expected {
                println!("Verification:  PASSED");
            } else {
                println!("Verification:  FAILED");
            }
        }
        Err(_) => eprintln!("Error: Input contained invalid hex characters."),
    };
}

pub fn run_challenge_2() {
    println!("----- Running Set 1 Challenge 2 Demo -----");

    let message = "1c0111001f010100061a024b53535009181c";
    let key = "686974207468652062756c6c277320657965";

    println!("Message (hex): {}", message);
    println!("Key (hex):     {}", key);

    // Decode Hex strings to Bytes
    let bytes_msg = hex::decode(message).expect("Invalid hex in message");
    let bytes_key = hex::decode(key).expect("Invalid hex in key");

    // Calculate XOR
    match fixed_xor(&bytes_msg, &bytes_key) {
        Ok(xor_bytes) => {
            let result_hex = hex::encode(xor_bytes);
            println!("Result (hex):  {}", result_hex);
            
            // Verify against the known solution
            let expected = "746865206b696420646f6e277420706c6179";
            if result_hex == expected {
                println!("Verification:  PASSED");
            } else {
                println!("Verification:  FAILED");
            }
        },
        Err(e) => println!("Error: {}", e),
    }
}

pub fn run_challenge_3() {
    println!("----- Running Set 1 Challenge 3 Demo -----");

    let hex_ciphertext = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    let ciphertext_bytes = hex::decode(hex_ciphertext).expect("Invalid hex string");

    let cracker = Cracker::SingleByteXor;
    let all_candidates = cracker.crack(&ciphertext_bytes, 3);

    // Print the winner
    if let Some(winner) = all_candidates.first() {
        println!("--- WINNER ---");
        println!("Score: {:.3}", winner.score);
        println!("Key: 0x{:02X}", winner.key[0]);
        println!("Message: {}", String::from_utf8_lossy(&winner.plaintext)); 
    }
}

pub fn run_challenge_4() {
    println!("----- Running Set 1 Challenge 4 Demo -----");
    
    let filepath = "data/4.txt";
    
    // Handle the error if file doesn't exist
    let lines = match read_lines(filepath) {
        Ok(l) => l,
        Err(_) => {
            eprintln!("Error: Could not read '{}'. Check your data folder.", filepath);
            return;
        }
    };
    
    let mut all_candidates: Vec<CrackResult> = Vec::new();
    let cracker = Cracker::SingleByteXor;

    // Process each line
    for line in lines {
        if let Ok(line_string) = line {
            let trimmed = line_string.trim();
            if trimmed.is_empty() { continue; }

            // Decode Hex
            if let Ok(bytes) = hex::decode(trimmed) {
                // Get top 1 result for this line
                let mut line_results = cracker.crack(&bytes, 1); 
                
                if let Some(best) = line_results.pop() {
                    all_candidates.push(best);
                }
            }
        }
    }

    // Find the global winner
    all_candidates.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap());

    // Print the winner
    if let Some(winner) = all_candidates.first() {
        println!("--- WINNER ---");
        println!("Score: {:.3}", winner.score);
        println!("Key: 0x{:02X}", winner.key[0]);
        println!("Message: {}", String::from_utf8_lossy(&winner.plaintext)); 
    }
}

fn read_lines<P>(filepath: P) -> io::Result<io::Lines<io::BufReader<File>>> where P: AsRef<Path>, {
    let file = File::open(filepath)?;
    Ok(io::BufReader::new(file).lines())
}

pub fn run_challenge_5() {
    
}

pub fn run_challenge_6() {
    
}

struct Oracle {
    key: Vec<u8>,
}

impl Oracle {
    fn new() -> Self {
        // SHOULD BE RANDOM
        Self { key: b"JOHN FRUSCIANTE".to_vec() } 
    }

    fn authenticate_user(&self, message: &[u8]) -> (Vec<u8>, [u8; 20]) {
        let mac = crate::crypto::secret_prefix_mac(&self.key, message);
        (message.to_vec(), mac)
    }

    fn validate(&self, message: &[u8], mac: &[u8; 20]) -> bool {
        let expected = crate::crypto::secret_prefix_mac(&self.key, message);
        &expected == mac
    }
}

pub fn run_challenge_29() {
    println!("----- Running Set 4 Challenge 29 Demo -----");
    let oracle = Oracle::new();

    // The attacker intercepts this specific message
    let initial_message = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon";
    let (original_msg, original_mac) = oracle.authenticate_user(initial_message);

    println!("Original Message: {:?}", String::from_utf8_lossy(&original_msg));
    println!("Original MAC:     {}", hex::encode(original_mac));

    println!("\nAttempting Length Extension Attack...");

    let new_suffix = b";admin=true";
    let registers = get_registers(&original_mac);
    for key_len_guess in 1..=128 {
        let dummy_prefix = vec![0u8; key_len_guess + original_msg.len()];
        let glue_padding = md_padding(&dummy_prefix);
        let total_bytes_processed = (key_len_guess + original_msg.len() + glue_padding.len()) as u64;

        let forged_mac = sha1_modified(new_suffix, &registers, total_bytes_processed);
        let mut forged_msg = original_msg.clone();
        forged_msg.extend_from_slice(&glue_padding);
        forged_msg.extend_from_slice(new_suffix);

        if oracle.validate(&forged_msg, &forged_mac) {
            println!("SUCCESS! KEy length guess: {}", key_len_guess);
            println!("Forged MAC: {}", hex::encode(forged_mac));
            println!("Full forged message: {}", hex::encode(forged_msg));
            return;
        }
    }

    println!("Attack failed.");
}