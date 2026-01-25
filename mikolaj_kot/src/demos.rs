use crate::block_crypto::{ ModeOfOperation };
use crate::cracker::{ Cracker, CrackResult };
use crate::number_theoretic_crypto::{ 
    Client, MODPGroupForIKE, Server, compute_dh_shared_secret, generate_dh_keypair 
};
use crate::utils::{ get_registers, hex_to_base64, modpow };
use crate::xor::{ fixed_xor, md_padding, repeating_xor, sha1_modified }; 

use num_bigint::BigUint;
use rand::{ Rng, SeedableRng, };
use rand_chacha::ChaCha20Rng;
use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;

// ╔═══════════════════════════════════════════════════════════════════════════════════════════════╗
// ║                                                                                               ║
// ║                                      SET 1 CHALLENGES                                         ║
// ║                                                                                               ║
// ╚═══════════════════════════════════════════════════════════════════════════════════════════════╝
pub fn run_challenge_1() {
    println!("----- Running Set 1 Challenge 1 Demo -----");
    
    let hex_string = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f757\
    3206d757368726f6f6d";
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
}// ════════════════════════════════════════════════════════════════════════════════════════════════

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
}// ════════════════════════════════════════════════════════════════════════════════════════════════

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
}// ════════════════════════════════════════════════════════════════════════════════════════════════

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
}// ════════════════════════════════════════════════════════════════════════════════════════════════

fn read_lines<P>(filepath: P) -> io::Result<io::Lines<io::BufReader<File>>> where P: AsRef<Path>, {
    let file = File::open(filepath)?;
    Ok(io::BufReader::new(file).lines())
}// ════════════════════════════════════════════════════════════════════════════════════════════════

pub fn run_challenge_5() {
    println!("----- Running Set 1 Challenge 5 Demo -----");

    let message = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
    let key = "ICE";
    
    let m_bytes = message.as_bytes();
    let k_bytes = key.as_bytes();

    println!("Message (hex):  {}", hex::encode(m_bytes));
    println!("Key (hex):  {}", hex::encode(k_bytes));

    let result_hex = hex::encode(repeating_xor(m_bytes, k_bytes));
    println!("Result (hex):  {}", result_hex);

    let expected = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282\
    b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
    if result_hex == expected {
        println!("Verification:  PASSED");
    } else {
        println!("Verification:  FAILED");
    }
}// ════════════════════════════════════════════════════════════════════════════════════════════════

pub fn run_challenge_6() {
    println!("----- Running Set 1 Challenge 5 Demo -----");

    let _file = File::open("data/6.txt");
    
}// ════════════════════════════════════════════════════════════════════════════════════════════════

pub fn run_challenge_7() {
    println!("----- Running Set 1 Challenge 7 Demo -----");

    let _mode_of_operation = ModeOfOperation::ECB;
    
}// ════════════════════════════════════════════════════════════════════════════════════════════════

// ╔═══════════════════════════════════════════════════════════════════════════════════════════════╗
// ║                                                                                               ║
// ║                                      SET 2 CHALLENGES                                         ║
// ║                                                                                               ║
// ╚═══════════════════════════════════════════════════════════════════════════════════════════════╝

// ╔═══════════════════════════════════════════════════════════════════════════════════════════════╗
// ║                                                                                               ║
// ║                                      SET 3 CHALLENGES                                         ║
// ║                                                                                               ║
// ╚═══════════════════════════════════════════════════════════════════════════════════════════════╝
// ═════════════════════════════════════ Set 4 Challenge 29 ════════════════════════════════════════
struct Oracle {
    key: Vec<u8>,
}

impl Oracle {
    fn new() -> Self {
        // SHOULD BE RANDOM
        Self { key: b"JOHN FRUSCIANTE".to_vec() } 
    }

    fn authenticate_user(&self, message: &[u8]) -> (Vec<u8>, [u8; 20]) {
        let mac = crate::xor::secret_prefix_mac(&self.key, message);
        (message.to_vec(), mac)
    }

    fn validate(&self, message: &[u8], mac: &[u8; 20]) -> bool {
        let expected = crate::xor::secret_prefix_mac(&self.key, message);
        &expected == mac
    }
}


pub fn run_challenge_29() {
    println!("----- Running Set 4 Challenge 29 Demo -----");
    let oracle = Oracle::new();

    // The attacker intercepts this specific message
    let initial_message = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20
    bacon";
    let (original_msg, original_mac) = oracle.authenticate_user(initial_message);

    println!("Original Message: {:?}", String::from_utf8_lossy(&original_msg));
    println!("Original MAC:     {}", hex::encode(original_mac));

    println!("\nAttempting Length Extension Attack...");

    let new_suffix = b";admin=true";
    let registers = get_registers(&original_mac);
    for key_len_guess in 1..=128 {
        let dummy_prefix = vec![0u8; key_len_guess + original_msg.len()];
        let padding = md_padding(&dummy_prefix);
        let total_bytes_processed = (key_len_guess + original_msg.len() + padding.len()) as u64;

        let forged_mac = sha1_modified(new_suffix, &registers, total_bytes_processed);
        let mut forged_msg = original_msg.clone();
        forged_msg.extend_from_slice(&padding);
        forged_msg.extend_from_slice(new_suffix);

        if oracle.validate(&forged_msg, &forged_mac) {
            println!("SUCCESS! Key length guess: {}", key_len_guess);
            println!("Forged MAC: {}", hex::encode(forged_mac));
            println!("Full forged message: {}", hex::encode(forged_msg));
            return;
        }
    }

    println!("Attack failed.");
}// ════════════════════════════════════════════════════════════════════════════════════════════════

// ╔═══════════════════════════════════════════════════════════════════════════════════════════════╗
// ║                                                                                               ║
// ║                                      SET 5 CHALLENGES                                         ║
// ║                                                                                               ║
// ╚═══════════════════════════════════════════════════════════════════════════════════════════════╝
// ═════════════════════════════════════ Set 5 Challenge 33 ════════════════════════════════════════
/// Challenge: Implement Diffie-Hellman Key Exchange
///
/// Assumption: Alice and Bob want to agree on a secret key over a public network.
/// They have no prior secrets, and an attacker is watching every message they send.
///
/// The Algorithm:
/// 1. They agree on a large prime (p) and a generator (g).
///    Everyone, including the attacker, knows these.
/// 2. Exchange: 
///    * Alice picks a secret (a) and sends her public share A = g^a mod p.
///    * Bob picks a secret (b) and sends his public share B = g^b mod p.
/// 3. Derivation:
///    * Alice computes S = B^a mod p.
///    * Bob computes S = A^b mod p.
///    * Since (g^b)^a = (g^a)^b, they now share the exact same secret S,
///      which the attacker cannot calculate without solving the Discrete Log problem.
///
pub fn run_challenge_33() {
    println!("----- Running Set 5 Challenge 33 Demo -----");
    
    println!("--- Small Number DH Simulation ---");
    let p: u32  = 37;
    let g: u32  = 5;
    println!("p: {}, g: {}", p, g);
    
    // Initialize random number generator
    let mut rng = ChaCha20Rng::from_entropy();

    // Generate private keys
    let priv_alice: u32 = rng.r#gen::<u32>() % p;
    let priv_bob: u32 = rng.r#gen::<u32>() % p;

    // Generate public keys
    let pub_alice: u32 = modpow(g, priv_alice, p);
    let pub_bob: u32 = modpow(g, priv_bob, p);
    println!("Alice's Public Key: {}", pub_alice);
    println!("Bob's Public Key:   {}", pub_bob);

    // Calculate shared secrets
    let s_alice: u32 = modpow(pub_bob, priv_alice, p) ;
    let s_bob: u32 = modpow(pub_alice, priv_bob, p);

    assert_eq!(s_alice, s_bob);
    println!("Verification:  PASSED");
    println!("Shared Secret: {}\n", s_alice);
    // --------------------------------

    println!("--- Big Number DH Simulation ---");
    let dh_group = MODPGroupForIKE::Group5;
    let group = dh_group.get_group();

    // Pass a reference to the group data
    let alice = generate_dh_keypair(&group);
    let bob = generate_dh_keypair(&group);

    // Calculate shared secrets
    let s_alice = compute_dh_shared_secret(&alice.priv_key, &bob.pub_key, &group);
    let s_bob = compute_dh_shared_secret(&bob.priv_key, &alice.pub_key, &group);
    
    // Display results
    println!("Alice's Secret: {:x}", s_alice);
    println!("Bob's Secret:   {:x}", s_bob);
    
    // Verify both shared secrets match
    assert_eq!(s_alice, s_bob);
    println!("Verification:  PASSED");
    println!("Shared Secret: {}\n", s_alice);
    // --------------------------------

    println!("Diffie-Hellman Key Exchange simulation completed successfully.");
}// ════════════════════════════════════════════════════════════════════════════════════════════════

// ═════════════════════════════════════ Set 5 Challenge 33 ════════════════════════════════════════
pub fn run_challenge_34() {
    println!("----- Running Set 5 Challenge 34 Demo -----");
    unimplemented!();
}// ════════════════════════════════════════════════════════════════════════════════════════════════

// ═════════════════════════════════════ Set 5 Challenge 33 ════════════════════════════════════════
pub fn run_challenge_35() {
    println!("----- Running Set 5 Challenge 35 Demo -----");
    unimplemented!();
}// ════════════════════════════════════════════════════════════════════════════════════════════════

// ═════════════════════════════════════ Set 5 Challenge 36 ════════════════════════════════════════
/// Challenge: Building the SRP Protocol
///
/// Assumptions: Both the client and server know the main setup values (N, g, k), the user's ID, 
/// and the password. During registration, the server doesn't save the actual password. Instead, it
/// generates a random salt and a "Verifier" (v). This is for extra security because if the 
/// server's database gets hacked, the adversary only gets the verifier, not the password itself.
///
/// The Goal: We want a "Zero-Knowledge Proof." Basically, the client needs to prove
/// they know the password to get a shared session key (K), but they have to do it
/// without ever sending the password or the verifier over the internet.
///
/// 1. Making the Symmetric Key & Managing It
///    * Both sides do their own math to find a shared secret (S). The client uses their random key
///      "a" and the server uses their random key "b," plus a scrambling value "u" they both 
///      calculate.
///    * Since "S" is just a giant number, we run it through SHA256 to get "K." This gives us a 
///      strong 256-bit key that works perfectly for such things as AES encryption.
///    * Those random keys "a" and "b" are temporary—we drop them as soon as the handshake is done.
///      Because these keys change every time, the final key "K" is unique for every single login.
///      This stops "replay attacks" where a hacker tries to reuse an old login session.
///
/// 2. Using HMAC for Message Authentication
///    * Once the client has the shared session key they have to prove they got the shared secret. 
///      But they cannoy just send "K" directly in case of eavesdropping.
///    * The client calculates an HMAC-SHA256 using "K" as the key and the "salt" as the message. 
///      One can only get the right HMAC if they actually know the secret key "K." Including the 
///      salt makes sure this proof only works for this specific user and this specific attempt.
///    * The server does the same HMAC math on its side. If the server's result matches
///      what the client sent, the server knows the client is legit and responds with "OK."
///    * This protocol is considered safe because HMAC is considered a one-way function. 
///      An eavesdropper can see the HMAC result but cannot work backward to find "K" or 
///      the password.
///
pub fn run_challenge_36() {
    println!("----- Running Set 5 Challenge 36 Demo -----");
    
    // Initialise the Server
    let mut server = Server::new();

    // Initialise the Client
    let mut client = Client::new(
        "pepper@noncense.hack",
        b"ultrasuperhrupersecurepassword",
        MODPGroupForIKE::Group15,
        BigUint::from(3u32),
    );

    // Register the user
    println!("\nRegistering user '{}'...", &client.username());

    server.register(
        client.username(), 
        client.password(), 
        client.group(),
        client.k()
    );
    println!("Registration complete.");

    // Start handshake
    println!("\nClient: Starting login handshake...");
    let (username, client_pub_key) = client.start_handshake();
    println!("Client: Sent username ({}) and public key ({:x}).", username, client_pub_key);

    // Server handles login request
    let (salt, server_pub_key, session_id) = 
        server.handle_login_request(&username, client_pub_key.clone());
    println!("Server: Responded with salt ({}) and public key ({:x}).", hex::encode(&salt), server_pub_key);
    
    // Client continues handshake
    let session_key = client.continue_handshake(&salt, server_pub_key, client_pub_key);
    println!("Client: Computed session key and sent verification to server.");

    // Server verifies login
    println!("Server: Verifying login...");
    if server.verify_login(&session_id, &session_key.as_slice()) {
        println!("Server: OK");
    } else {
        println!("Server: VERIFICATION FAILED");
    }
}// ════════════════════════════════════════════════════════════════════════════════════════════════

// ═════════════════════════════════════ Set 5 Challenge 39 ════════════════════════════════════════
/// Challenge: Implementing Textbook RSA
///
/// Security relies on the fact that multiplying two huge prime numbers is easy, but factoring 
/// the result back into primes is incredibly hard.
///
/// 1. We generate two large primes (p and q) and multiply them to get the modulus N.
/// 2. We pick a public exponent e (usually 65537, because 3 can contribute to vulnerabilities) and 
///    calculate a private exponent d. These are linked in such a way that d undoes what e does (and
///    vice versa).
/// 3. We turn the message into a number M and compute C = M^e mod N. 
///    To decrypt, we compute P = C^d mod N to get back M.
/// 
pub fn run_challenge_39() {
    println!("----- Running Set 5 Challenge 39 Demo -----");
    let message = "JOHN FRUSCIANTE IS A GUITAR GOD!";
    let message_bytes = message.as_bytes();
    let message_integer = BigUint::from_bytes_be(message_bytes);

    let rsa_keypair = crate::number_theoretic_crypto::RSAKeyPair::new();
    println!("Public Key (n): {}", rsa_keypair.n);
    println!("Public Exponent (e): {}", rsa_keypair.e);

    let ciphertext = rsa_keypair.encrypt(&message_integer);
    println!("Ciphertext: {}", hex::encode(ciphertext.to_bytes_be()));

    let plaintext = rsa_keypair.decrypt(&ciphertext);
    let plaintext_bytes = plaintext.to_bytes_be();
    let decrypted_message = String::from_utf8_lossy(plaintext_bytes.as_slice());
    println!("Decrypted Message: {}", decrypted_message);

    if decrypted_message == message {
        println!("Verification:  PASSED");
    } else {
        println!("Verification:  FAILED");
    }
}// ════════════════════════════════════════════════════════════════════════════════════════════════

// ═════════════════════════════════════ Set 5 Challenge 39 ════════════════════════════════════════
/// Challenge: E=3 RSA Broadcast Attack
///
/// Assumption: You send the exact same message to three different friends.
/// They all have different public keys (N), but they all use the same small exponent (e=3).
///
/// Method: Because the message is identical and the exponent is tiny, the math
/// overlaps in a way that allows an attacker to bypass the security entirely without
/// needing the private keys:
///    * The combined modulus is much larger than the message cubed.
///    * Because the number isn't big enough to overflow the modulus, the mod operation is useless.
///    * We just calculate the cube root of the CRT result, and obtain the original plaintext.
/// 
pub fn run_challenge_40() {
    println!("----- Running Set 5 Challenge 40 Demo -----");
    let hidden_message = "\
    Easily let's get carried away \
    Easily let's get married today \
    Shao Lin shouted a rose from his throat \
    Everything must go \
    ";
    let message_bytes = hidden_message.as_bytes();
    let message_integer = BigUint::from_bytes_be(message_bytes);

    println!("Attempting E=3 RSA Broadcast Attack...");
    let vuln_rsa_keypair_0 = crate::number_theoretic_crypto::RSAKeyPair::new_e3();
    let vuln_rsa_keypair_1 = crate::number_theoretic_crypto::RSAKeyPair::new_e3();
    let vuln_rsa_keypair_2 = crate::number_theoretic_crypto::RSAKeyPair::new_e3();

    println!("Ciphertexts and public keys obtained!");
    println!("-------------------------------------");
    let c_0 = vuln_rsa_keypair_0.encrypt(&message_integer);
    println!("Ciphertext 0: {}\nKey 0: {}", hex::encode(c_0.to_bytes_be()), vuln_rsa_keypair_0.n);
    println!("-------------------------------------");
    let c_1 = vuln_rsa_keypair_1.encrypt(&message_integer);
    println!("Ciphertext 1: {}\nKey 1: {}", hex::encode(c_1.to_bytes_be()), vuln_rsa_keypair_1.n);
    println!("-------------------------------------");
    let c_2 = vuln_rsa_keypair_2.encrypt(&message_integer);
    println!("Ciphertext 2: {}\nKey 2: {}", hex::encode(c_2.to_bytes_be()), vuln_rsa_keypair_2.n);
    println!("-------------------------------------");

    let ciphertexts = vec![c_0, c_1, c_2];
    let moduli = vec![
        vuln_rsa_keypair_0.n.clone(), 
        vuln_rsa_keypair_1.n.clone(), 
        vuln_rsa_keypair_2.n.clone()
    ];

    let recovered_message_int = crate::number_theoretic_crypto::rsa_broadcast_attack_e3(
        &ciphertexts,
        &moduli,
    );

    let recovered_string = String::from_utf8_lossy(&recovered_message_int.to_bytes_be())
        .to_string();
    println!("Recovered: {}", recovered_string);
    if recovered_string == hidden_message {
        println!("Verification:  PASSED");
    } else {
        println!("Verification:  FAILED");
    }
}// ════════════════════════════════════════════════════════════════════════════════════════════════
