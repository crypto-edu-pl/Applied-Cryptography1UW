// src/number_theoretic_crypto.rs
use crate::crypto_constants::*;
use crate::hashing::{ sha2, };
use crate::utils::{ cube_root, invmod, gcd, generate_large_prime, };

use num_bigint::{ BigUint, RandomBits, };
use num_traits::{ Num, One, };
use rand_chacha::ChaCha20Rng;
use rand::{ Rng, RngCore, SeedableRng, };
use std::collections::HashMap;

// Default MODP Group for IKE (Group15 - 3072-bit)
pub const DEFAULT_DH_GROUP: MODPGroupForIKE = MODPGroupForIKE::Group15;

#[derive(Debug, Clone)]

// Structure representing a MODP Group with prime modulus and generator
pub struct MODPGroup {
    pub p: BigUint, // The prime modulus
    pub g: BigUint, // The generator
}

// Enumeration for MODP Groups used in Internet Key Exchange (IKE)
#[derive(Debug, Clone, Copy)]
pub enum MODPGroupForIKE {
    #[deprecated(
        note = "Group 5 is insecure. Please use Group14 or higher.",
    )]
    Group5 = 5,   // [DEPRECATED] MODP 1536-bit
    #[deprecated(
        note = "Group 14 is a Legacy group. \
        It has been approved until 2030 but consider using a stronger group.",
    )]
    Group14 = 14, // [LEGACY] MODP 2048-bit
    Group15 = 15, // MODP 3072-bit
    Group16 = 16, // MODP 4096-bit
    Group17 = 17, // [PARANOIA] MODP 6144-bit
    Group18 = 18, // [PARANOIA] MODP 8192-bit
}

// Method to get MODPGroup from MODPGroupForIKE
impl MODPGroupForIKE {
    pub fn get_group(&self) -> MODPGroup {
        let p_hex = match self {
            Self::Group5 => GROUP5_P_HEX,
            Self::Group14 => GROUP14_P_HEX,
            Self::Group15 => GROUP15_P_HEX,
            Self::Group16 => GROUP16_P_HEX,
            Self::Group17 => GROUP17_P_HEX,
            Self::Group18 => GROUP18_P_HEX,
        };

        MODPGroup {
            p: BigUint::from_str_radix(p_hex, 16).expect("Invalid Hex in Constants"),
            g: BigUint::from(G_VAL),
        }
    }
}

// Conversion from MODPGroupForIKE to MODPGroup
impl From<MODPGroupForIKE> for MODPGroup {
    fn from(group: MODPGroupForIKE) -> Self {
        group.get_group()
    }
}

// DH Keypair structure
pub struct KeyPair {
    pub priv_key: BigUint,
    pub pub_key: BigUint,
}

// Generates a DH keypair given a MODP group
pub fn generate_dh_keypair(group: &MODPGroup) -> KeyPair {
    let mut rng = ChaCha20Rng::from_entropy();
    // Use 256 bits for the private key as per RFC 7919 recommendation
    let priv_key = rng.sample(RandomBits::new(256));
    let pub_key = group.g.modpow(&priv_key, &group.p);

    KeyPair { priv_key, pub_key }
}

// Computes the DH shared secret given private key and peer's public key
pub fn compute_dh_shared_secret(
    priv_key: &BigUint,
    peer_pub_key: &BigUint,
    group: &MODPGroup, // Take the struct reference
) -> BigUint {
    peer_pub_key.modpow(priv_key, &group.p)
}

pub struct Client {
    username: String,
    password: Vec<u8>,
    group: MODPGroup,
    k: BigUint,
    sessions: HashMap<BigUint, BigUint>,
}

impl Client {
    pub fn new(username: &str, password: &[u8], group_choice: MODPGroupForIKE, k: BigUint) -> Self {
        Self {
            username: username.to_string(),
            password: password.to_vec(),
            group: group_choice.get_group(),
            k,
            sessions: HashMap::new(),
        }
    }

    // Starts the handshake by generating client's DH keypair
    pub fn start_handshake(&mut self) -> (String, BigUint) {
        // Pass the struct's group to generate_dh_keypair
        let KeyPair { priv_key, pub_key } = generate_dh_keypair(&self.group);
        
        self.sessions.insert(pub_key.clone(), priv_key);
        (self.username.clone(), pub_key)
    }

    // Continues the handshake after receiving salt and server's public key
    pub fn continue_handshake(
        &mut self, salt: &[u8],
        server_pub_key: BigUint,
        client_pub_key: BigUint
    ) -> Vec<u8> {
        let priv_key = self.sessions.remove(&client_pub_key).unwrap();

        // u = SHA256(A|B)
        let mut combined_pub_keys_be_bytes: Vec<u8> = client_pub_key.to_bytes_be();
        combined_pub_keys_be_bytes.extend_from_slice(&server_pub_key.to_bytes_be());
        let pub_keys_hash = sha2(&combined_pub_keys_be_bytes);
        let u = BigUint::from_bytes_be(&pub_keys_hash);

        // x = SHA256(salt || password)
        let mut hash_input = Vec::new();
        hash_input.extend_from_slice(salt);
        hash_input.extend_from_slice(&self.password);
        let password_hash = sha2(&hash_input);

        // S = (B - k * g**x) ** (a + u * x) % N
        let x = BigUint::from_bytes_be(&password_hash);
        let g_exp_x = self.group.g.modpow(&x, &self.group.p);
        let kgx_mod = (&self.k * g_exp_x) % &self.group.p;
        let base = if server_pub_key >= kgx_mod {
            server_pub_key - kgx_mod
        } else {     
            &self.group.p + server_pub_key - kgx_mod
        };
        let exponent = &priv_key + &u * &x;
        let shared_secret = base.modpow(&exponent, &self.group.p);

        // Derive session key
        let mut session_key_input = Vec::new();
        session_key_input.extend_from_slice(&shared_secret.to_bytes_be());

        let session_key = sha2(&session_key_input);

        session_key.to_vec()
    }

    pub fn username(&self) -> &str { &self.username }
    pub fn password(&self) -> &[u8] { &self.password }
    pub fn group(&self) -> MODPGroup { self.group.clone() }
    pub fn k(&self) -> BigUint { self.k.clone() }
}

// Server-side user fields
struct UserFields {
    salt: Vec<u8>,
    verifier: BigUint,
    group: MODPGroup,
    k: BigUint,
}

pub struct Server {
    rng: ChaCha20Rng,
    users: HashMap<String, UserFields>,  // username -> password, (N, g), k
    sessions: HashMap<Vec<u8>, Vec<u8>>, // session_id -> Sessions
}

impl Server {
    pub fn new() -> Self {
        Self {
            rng: ChaCha20Rng::from_entropy(), 
            users: HashMap::new(),
            sessions: HashMap::new(),
        }
    }

    // Registers a new user (username, salt, verifier, group, k) with the server
    pub fn register(&mut self, username: &str, password: &[u8], group: MODPGroup, k: BigUint) {
        let mut server_rng = ChaCha20Rng::from_entropy();
        let mut salt = [0u8; 16];
        server_rng.fill_bytes(&mut salt);
        
        let salted_hash = sha2(&[&salt[..], &password[..]].concat());
        let exponent = BigUint::from_bytes_be(&salted_hash);   
        let verifier = BigUint::modpow(
            &group.g,
            &exponent, 
            &group.p,
        );

        self.users.insert(
            username.to_string(),
            UserFields {
                salt: salt.to_vec(),
                verifier,
                group: group.clone(),
                k,
            },
        );
    }

    // Handles login request from client
    pub fn handle_login_request(
        &mut self,
        username: &str,
        client_pub_key: BigUint
    ) -> (Vec<u8>, BigUint, Vec<u8>) {
        let user = self.users.get(username).unwrap();
        
        let mut session_id=  [0u8; 16];
        self.rng.fill_bytes(&mut session_id);

        let KeyPair{ priv_key: dh_priv_key, pub_key: dh_pub_key } = generate_dh_keypair(
            &user.group
        );

        // B = kv + g**b % N
        let kv = &user.k * &user.verifier;
        let pub_key = (dh_pub_key + kv) % &user.group.p;

        // uH = SHA256(A|B)
        let mut combined_pub_keys_be_bytes: Vec<u8> = client_pub_key.to_bytes_be();
        combined_pub_keys_be_bytes.extend_from_slice(&pub_key.to_bytes_be());
        let public_hash = sha2(&combined_pub_keys_be_bytes);

        // u = integer of 
        let u = BigUint::from_bytes_be(&public_hash);
        
        // S = (A * v**u) ** b % N
        let v_u = &user.verifier.modpow(&u, &user.group.p);
        let s = (client_pub_key * v_u).modpow(&dh_priv_key, &user.group.p);
        
        // K = SHA256(S)
        let session_key_input = &s.to_bytes_be();
        let session_key = sha2(session_key_input);
   
        // save session to prevent replay
        self.sessions.insert(
            session_id.to_vec(),
            session_key.to_vec(),
        );

        (user.salt.clone(), pub_key, session_id.to_vec())
    }

    pub fn verify_login(&mut self, session_id: &[u8], hash: &[u8]) -> bool {
        if let Some(stored_session_key) = self.sessions.remove(session_id) {
            return hash == stored_session_key;
        }
        false
    }
}

pub struct RSAKeyPair {
    pub n: BigUint,
    pub e: BigUint,
    pub d: BigUint,
}

impl RSAKeyPair {
    pub fn new() -> Self {
        let e_val = BigUint::from(65537u32); 

        loop {
            // 512 bits combine to N of 1024 bits
            let p = generate_large_prime(512);
            let q = generate_large_prime(512);

            // Cloned to prevent ownership issues
            let p_minus_1 = &p - 1u32;
            let q_minus_1 = &q - 1u32;
            let totient = p_minus_1 * q_minus_1;

            // Cloned to prevent ownership issues
            let mut e_temp = e_val.clone();
            let mut tot_temp = totient.clone();
            
            if gcd(&mut e_temp, &mut tot_temp) == BigUint::one() {
                let n = p * q; 
                let d = invmod(&e_val, &totient);
                return Self { n, e: e_val, d };
            }
            // If the GCD !=1, the loop restarts, generating new p and q values.
        }
    }
    
    // Very small public exponent e=3
    pub fn new_e3() -> Self {
        let e_val = BigUint::from(3u32); 

        loop {
            let p = generate_large_prime(512);
            let q = generate_large_prime(512);

            let p_minus_1 = &p - 1u32;
            let q_minus_1 = &q - 1u32;
            let totient = p_minus_1 * q_minus_1;

            let mut e_temp = e_val.clone();
            let mut tot_temp = totient.clone();
            
            if gcd(&mut e_temp, &mut tot_temp) == BigUint::one() {
                let n = p * q; 
                
                let d = invmod(&e_val, &totient);

                return Self { n, e: e_val, d };
            }
            // If the GCD !=1, the loop restarts, generating new p and q values.
        }
    }

    pub fn encrypt(&self, plaintext: &BigUint) -> BigUint {
        plaintext.modpow(&self.e, &self.n)
    }

    pub fn decrypt(&self, ciphertext: &BigUint) -> BigUint {
        ciphertext.modpow(&self.d, &self.n)
    }
}

// RSA Broadcast Attack for e=3
pub fn rsa_broadcast_attack_e3(
    ciphertexts: &[BigUint],
    moduli: &[BigUint],
) -> BigUint {
    assert!(ciphertexts.len() == 3 && moduli.len() == 3, 
        "This attack requires exactly three ciphertexts and moduli."
    );

    let c1 = &ciphertexts[0];
    let c2 = &ciphertexts[1];
    let c3 = &ciphertexts[2];

    let n1 = &moduli[0];
    let n2 = &moduli[1];
    let n3 = &moduli[2];

    let n = n1 * n2 * n3;

    let m1 = &n / n1;
    let m2 = &n / n2;
    let m3 = &n / n3;

    let inv1 = invmod(&m1, n1);
    let inv2 = invmod(&m2, n2);
    let inv3 = invmod(&m3, n3);

    let x = (c1 * &m1 * &inv1 + c2 * &m2 * &inv2 + c3 * &m3 * &inv3) % &n;

    cube_root(&x)
}