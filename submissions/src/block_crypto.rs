use aes::Aes128;
use aes::cipher::{ Block, BlockDecrypt, BlockEncrypt, generic_array::GenericArray, KeyInit};
use std::io;
use typenum::U16;

const BLOCK_LEN: usize = 16;
const KEY_LEN: usize = 16;
const NONCE_LEN: usize = 16;

pub enum ModeOfOperation {
    CTR,
    CBC,
    ECB,
    OFB,
    CFB,
    GCM,
}

impl ModeOfOperation {
    fn _from_u8(num: u8) -> Option<ModeOfOperation> {
        match num {
            1 => Some(Self::CTR),
            2 => Some(Self::CBC),
            3 => Some(Self::ECB),
            4 => Some(Self::OFB),
            5 => Some(Self::CFB),
            6 => Some(Self::GCM),
            _ => None,
        }
    }

    fn _prompt() -> ModeOfOperation {
        loop {
            println!("Choose mode:\n\t1 - CTR\n\t2 - CBC\n\t3 - ECB\n\t4 - OFB\n\t5 - CFB\n\t6 - GCM");

            let mut mode_input = String::new();
            io::stdin()
                .read_line(&mut mode_input)
                .expect("Fail to read mode");

            let mode: u8 = match mode_input.trim().parse() {
                Ok(num) => num,
                Err(_) => {
                    println!("Invalid input! Try again.");
                    continue;
                },
            };

            let mode: ModeOfOperation = match ModeOfOperation::_from_u8(mode) {
                Some(m) => m,
                None => {
                    println!("Invalid mode! Try again.");
                    continue;
                }
            };

            break mode;
        }
    }

    pub fn encrypt(&self, key: &[u8], nonce_or_iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, &'static str> {
        if key.len() != KEY_LEN { return Err("Key must be 32 bytes for AES-128"); }

        let nonce = nonce_or_iv;
        let iv = nonce_or_iv;

        match self {
            ModeOfOperation::CTR => self.encrypt_ctr(key, nonce, plaintext),
            ModeOfOperation::CBC => self.encrypt_cbc(key, iv, plaintext),
            ModeOfOperation::ECB => self.encrypt_ecb(key, plaintext),
            ModeOfOperation::OFB => self.encrypt_ofb(key, iv, plaintext),
            ModeOfOperation::CFB => self.encrypt_cfb(key, iv, plaintext),
            ModeOfOperation::GCM => self.encrypt_gcm(key, nonce, plaintext),
        }
    }

    pub fn decrypt(&self, key: &[u8], nonce_or_iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, &'static str> {
        if key.len() != KEY_LEN { return Err("Key must be {KEY_LEN} bytes for AES-128"); }
        
        let nonce = nonce_or_iv;
        let iv = nonce_or_iv;

        match self {
            ModeOfOperation::CTR => self.encrypt_ctr(key, nonce, plaintext), // symmetric
            ModeOfOperation::CBC => self.decrypt_cbc(key, plaintext), // no iv needed for decryption (left in ciphertext)
            ModeOfOperation::ECB => self.decrypt_ecb(key, plaintext),
            ModeOfOperation::OFB => self.decrypt_ofb(key, iv, plaintext),
            ModeOfOperation::CFB => self.decrypt_cfb(key, plaintext),
            ModeOfOperation::GCM => self.decrypt_gcm(key, nonce, plaintext),
        }
    }

    fn encrypt_ctr(&self, key: &[u8], nonce: &[u8], plaintext: &[u8])-> Result<Vec<u8>, &'static str> {
        if nonce.len() != NONCE_LEN { return Err("Nonce must be 16 bytes for CTR"); }

        // Initialise
        let cipher = Aes128::new_from_slice(key).expect("Failed to create cipher");
        let mut ciphertext: Vec<u8> = Vec::with_capacity(plaintext.len());
        let mut counter_block_bytes: [u8; NONCE_LEN] = nonce.try_into().unwrap(); // Nonce
        
        
        for p_block in plaintext.chunks(BLOCK_LEN) {
            // PSEUDOCODE: `ks[i] = AES_Enc(k, nonce || i)`
            //---------------------------------------------
            let mut keystream_input_block = Block::<Aes128>::clone_from_slice(&counter_block_bytes);
            cipher.encrypt_block(&mut keystream_input_block);
            //---------------------------------------------

            // PSEUDOCODE: `c[i] = m[i] XOR ks[i]`
            //------------------------------------
            for (i, p_byte) in p_block.iter().enumerate() {
                let ks_byte = keystream_input_block[i];
                ciphertext.push(ks_byte ^ p_byte);
            }
            //------------------------------------

            // PSEUDOCODE: `i++`
            //------------------------------------
            for byte in counter_block_bytes.iter_mut().rev() { // iter_mut is key to modifying nonce
                let (_val, overflow) = byte.overflowing_add(1);
                if !overflow { break; }
            }
            //------------------------------------
        }

        Ok(ciphertext)
    }

    fn encrypt_cbc(&self, key: &[u8], iv: &[u8], plaintext: &[u8])-> Result<Vec<u8>, &'static str> {
        if iv.len() != BLOCK_LEN { return Err("IV must be {BLOCK_LEN} bytes for AES-CBC"); }

        let cipher = Aes128::new_from_slice(key).expect("Failed to create cipher");

        let p_len = plaintext.len();
        let mut ciphertext: Vec<u8> = Vec::with_capacity((p_len / BLOCK_LEN + 2) * BLOCK_LEN);
        let mut xor_res = GenericArray::default();

        ciphertext.extend_from_slice(iv);

        let mut chunks_iter = plaintext.chunks_exact(BLOCK_LEN);

        for (p_idx, p_block) in (&mut chunks_iter).enumerate() {
            // Prepare ciphertext block
            let prev_c_block_start = p_idx * BLOCK_LEN; // readability
            let prev_c_block = &ciphertext[prev_c_block_start..prev_c_block_start + BLOCK_LEN];
            
            // Copy ciphertext block
            xor_res.copy_from_slice(&prev_c_block); 

            // XOR in-place
            for (x_byte, p_byte) in xor_res.iter_mut().zip(p_block.iter()) {
                *x_byte ^= *p_byte;
            }

            cipher.encrypt_block(&mut xor_res); 
            ciphertext.extend_from_slice(&xor_res);
        }

        let remainder = chunks_iter.remainder();
        let pad_len = (BLOCK_LEN - remainder.len()) as u8;

        let mut last_block = [pad_len; BLOCK_LEN];
        last_block[..remainder.len()].copy_from_slice(remainder);

        for (i, p_byte) in last_block.iter().enumerate() {
            xor_res[i] = ciphertext[p_len / BLOCK_LEN * BLOCK_LEN + i] ^ p_byte;
        }

        cipher.encrypt_block(&mut xor_res); 
        ciphertext.extend_from_slice(&xor_res);            

        return Ok(ciphertext)
    }

    fn decrypt_cbc(&self, key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, &'static str> {
        if ciphertext.len() <  BLOCK_LEN * 2 {
            return Err("Ciphertext must be at least two blocks long");
        }
        if ciphertext.len() % BLOCK_LEN != 0 {
            return Err("Ciphertext must be a multiple of {BLOCK_LEN} bytes long for AES-CBC");
        }

        let cipher = Aes128::new_from_slice(key).expect("Failed to create cipher");
        let mut plaintext = Vec::with_capacity(ciphertext.len() - BLOCK_LEN);
        let mut xor_res = GenericArray::default();

        let mut c_blocks = ciphertext.chunks_exact(BLOCK_LEN);

        if let Some(mut prev_block) = c_blocks.next() { 
            while let Some(cur_block) = c_blocks.next() {
                xor_res.copy_from_slice(cur_block);
                cipher.decrypt_block(&mut xor_res);

                for (x_byte, c_byte) in xor_res.iter_mut().zip(prev_block.iter()) {
                    *x_byte ^= c_byte;
                }

                plaintext.extend_from_slice(&xor_res);

                prev_block = cur_block
            }
        }

        let p_len = plaintext.len();
        if p_len == 0 {
            return Err("Empty ciphertext provided - no pre-image under CBC due to padding")
        }

        let pad_len: usize = plaintext[p_len - 1] as usize;
        if pad_len == 0 || pad_len > BLOCK_LEN {
            return Err("Invalid padding value");
        }
        if (pad_len as usize) > p_len {
            return Err("Invalid padding: padding length longer than plaintext");
        }
    
        let unpadded_len = p_len - pad_len as usize;
        for &b in &plaintext[unpadded_len..] {
            if b != (pad_len as u8) {
                return Err("Invalid padding data: mismatch");
            }
        }

        plaintext.truncate(unpadded_len.into());

        return Ok(plaintext)
    }

    fn encrypt_ecb(&self, key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, &'static str> {
        let cipher = Aes128::new_from_slice(key).expect("Failed to create cipher");
        let mut ciphertext = Vec::with_capacity((plaintext.len() / BLOCK_LEN + 1) * BLOCK_LEN);

        let mut p_full_blocks = plaintext.chunks_exact(BLOCK_LEN);

        for (p_idx, p_block) in p_full_blocks.by_ref().enumerate() {
            ciphertext.extend_from_slice(&p_block);
            let c_block_mut_slice = &mut ciphertext[p_idx * BLOCK_LEN..(p_idx + 1) * BLOCK_LEN];

            cipher.encrypt_block(GenericArray::from_mut_slice(c_block_mut_slice));
        }

        let remainder = p_full_blocks.remainder();
        ciphertext.extend_from_slice(remainder);

        let pad_len  = (BLOCK_LEN - remainder.len()) as u8;
        
        for _i in remainder.len()..BLOCK_LEN {
            ciphertext.push(pad_len);
        }

        let c_block_mut_slice = &mut ciphertext[(plaintext.len() / BLOCK_LEN)..];
        cipher.encrypt_block(GenericArray::from_mut_slice(c_block_mut_slice));

        return Ok(ciphertext)
    }

    fn decrypt_ecb(&self, key: &[u8], ciphertext: &[u8])-> Result<Vec<u8>, &'static str> {
        if ciphertext.len() <  BLOCK_LEN {
            return Err("Ciphertext must have at least one full block");
        }

        let cipher = Aes128::new_from_slice(key).expect("Failed to create cipher");
        let mut plaintext = Vec::with_capacity(ciphertext.len());

        for (c_idx, c_block) in ciphertext.chunks_exact(BLOCK_LEN).enumerate() {
            plaintext.extend_from_slice(c_block);
            let p_block_mut_slice = &mut plaintext[c_idx * BLOCK_LEN..(c_idx + 1) * BLOCK_LEN];
            cipher.decrypt_block(GenericArray::from_mut_slice(p_block_mut_slice));
        }

        // p_len is at least BLOCK_LEN, so no need for that check
        let p_len = plaintext.len();

        let pad_len: usize = plaintext[p_len - 1] as usize;
        if pad_len == 0 || pad_len > BLOCK_LEN {
            return Err("Invalid padding value");
        }

        let pad_val = pad_len as u8;
        let unpadded_len = p_len - pad_len;
        for &b in &plaintext[unpadded_len..] {
            if b != pad_val {
                return Err("Invalid padding data: mismatch");
            }
        }

        plaintext.truncate(unpadded_len);

        return Ok(plaintext)
    }

    fn encrypt_ofb(&self, key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, &'static str> {
        if iv.len() != BLOCK_LEN { return Err("IV must be {BLOCK_LEN} bytes for AES-OFB"); }

        let cipher = Aes128::new_from_slice(key).expect("Failed to create cipher");
        let mut ciphertext = Vec::with_capacity(plaintext.len());

        let mut c_block = [0u8; BLOCK_LEN];
        let mut feedback_block = GenericArray::clone_from_slice(iv);
        let p_blocks = plaintext.chunks(BLOCK_LEN);

        for p_block in p_blocks {
            cipher.encrypt_block(&mut feedback_block);
            
            for i in 0..p_block.len() {
                c_block[i] = p_block[i] ^ feedback_block[i];
            }
            ciphertext.extend_from_slice(&c_block[..p_block.len()]);
        }

        return Ok(ciphertext)
    }

    fn decrypt_ofb(&self, key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, &'static str> {
        if iv.len() != BLOCK_LEN { return Err("IV must be {BLOCK_LEN} bytes for AES-OFB"); }

        let cipher = Aes128::new_from_slice(key).expect("Failed to create cipher");
        let mut plaintext = Vec::with_capacity(ciphertext.len());

        let mut p_block = [0u8; BLOCK_LEN];
        let mut feedback_block = GenericArray::clone_from_slice(iv);
        let c_blocks = ciphertext.chunks(BLOCK_LEN);

        for c_block in c_blocks {
            cipher.encrypt_block(&mut feedback_block);
            
            for i in 0..c_block.len() {
                p_block[i] = c_block[i] ^ feedback_block[i];
            }
            plaintext.extend_from_slice(&p_block[..c_block.len()]);
        }

        return Ok(plaintext)
    }

    fn encrypt_cfb(&self, key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, &'static str> {
        if iv.len() != BLOCK_LEN { return Err("IV must be {BLOCK_LEN} bytes for AES-CFB"); }
    
        let cipher = Aes128::new_from_slice(key).expect("Failed to create cipher");
        let mut ciphertext = Vec::with_capacity(plaintext.len() + BLOCK_LEN);
        ciphertext.extend_from_slice(iv);

        let mut temp_block = [0u8; BLOCK_LEN];

        for (p_idx, p_block) in plaintext.chunks(BLOCK_LEN).enumerate() {
            temp_block.copy_from_slice(&ciphertext[BLOCK_LEN * p_idx..(p_idx + 1) * BLOCK_LEN]);
            cipher.encrypt_block(GenericArray::from_mut_slice(&mut temp_block));

            ciphertext.extend_from_slice(&temp_block[0..p_block.len()]);
            let cur_block = &mut ciphertext[BLOCK_LEN * (1 + p_idx)..(p_idx + 1) * BLOCK_LEN + p_block.len()];
            for (c_byte, p_byte) in cur_block.iter_mut().zip(p_block.iter()) {
                *c_byte ^= *p_byte;
            }
        }
        
        return Ok(ciphertext)
    }

    fn decrypt_cfb(&self, key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, &'static str> {
        if ciphertext.len() < BLOCK_LEN { return Err("Ciphertext must be at least {BLOCK_LEN} bytes for AES-CFB (IV)."); }

        let cipher = Aes128::new_from_slice(key).expect("Failed to create cipher");
        let mut plaintext = Vec::with_capacity(ciphertext.len());
        
        for (c_idx, c_block) in ciphertext.chunks(BLOCK_LEN).skip(1).enumerate() {
            let mut temp_block: GenericArray<u8, U16> = GenericArray::
                clone_from_slice(&ciphertext[BLOCK_LEN * c_idx..(c_idx + 1) * BLOCK_LEN]);
            cipher.encrypt_block(&mut temp_block);

            plaintext.extend_from_slice(&temp_block[0..c_block.len()]);
            let p_block = &mut plaintext[BLOCK_LEN * c_idx..c_idx * BLOCK_LEN + c_block.len()];
            for (p_byte, c_byte) in p_block.iter_mut().zip(c_block.iter()) {
                *p_byte ^= *c_byte;
            }   
        }

        return Ok(plaintext)
    }

    fn encrypt_gcm(&self, key: &[u8], nonce: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, &'static str> {
        if nonce.len() != BLOCK_LEN { return Err("Nonce must be {BLOCK_LEN} bytes for AES-GCM"); }
    
        let _cipher = Aes128::new_from_slice(key).expect("Failed to create cipher");
        let ciphertext = Vec::with_capacity(plaintext.len());
        
        /* TO DO */

        return Ok(ciphertext)
    }

    fn decrypt_gcm(&self, key: &[u8], nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, &'static str> {
        if nonce.len() != BLOCK_LEN { return Err("Nonce must be {BLOCK_LEN} bytes for AES-GCM"); }

        let _cipher = Aes128::new_from_slice(key).expect("Failed to create cipher");
        let plaintext = Vec::with_capacity(ciphertext.len());

        /* TO DO */

        return Ok(plaintext)
    }

    /**
     * Applies PKCS#7 padding to a mutable byte vector in-place.
     */
    fn _pkcs7(bytes: &mut Vec<u8>) {
        let n_padding: u8 = ((BLOCK_LEN - (bytes.len() % BLOCK_LEN) % BLOCK_LEN)) as u8;
        for _ in 0..n_padding {
            bytes.push(n_padding);
        }
    }
}

/* 
 * CTR mode short exercises
 */
fn _exercise1() {
    /* 1. Compute ciphertext for m = 0x11223344 and keystream ks = 0xAABBCCDD. */
    let m: u32 = 0x11223344;
    let ks: u32 = 0xAABBCCDD;
    let c: u32 = m ^ ks;

    /* 2. Flip bit 3 of a ciphertext byte. Determine which bit of plaintext changes. */
    let c_ = c ^ 0x8;
    let m_ = c_ ^ ks;
    println!("{:x?}", m_);
    
    /* 3. Explain why reusing nonce+counter breaks security.  */
    // Because the keystream is not randomised (by the nonce), 
    //+which is vulnerable to the two-time pad attack.
}

/* 
 * CBC mode short exercises
 */
fn _exercise2() {
    /* 1. Compute ciphertext for m = 0x11223344 and keystream ks = 0xAABBCCDD. */
    let m = "ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEF";
    let k: [u8; KEY_LEN] = [0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF];
    let iv: [u8; BLOCK_LEN] = [0x11,  0x13, 0x1B, 0x1C, 0x12, 0x12, 0x18, 0x10, 0x18, 0x91, 
        0x3A, 0x3B, 0xCC, 0xAC, 0xCE, 0x00];
    let mode = ModeOfOperation::CBC;

    let mut ciphertext_bytes: Vec<u8> = mode.encrypt(&k, &iv, m.as_bytes()).expect("Encryption failed");
    println!("Ciphertext bytes (hex): {:x?}", ciphertext_bytes);
    
    /* 2. Flip a bit in C1 and identify changes in plaintext. */
    ciphertext_bytes[0] ^= 0100;
    let retrieved_plaintext = mode.decrypt(&k, &iv, &ciphertext_bytes).expect("Decryption failed");
    println!("Retrieved plaintext (hex): {:x?}", retrieved_plaintext);
    
    /* 3. Does CBC provide integrity? Explain.  */
    // 
}

fn _read_input() -> Vec<u8> {
    let mut plaintext = String::new();

    println!("Enter the plaintext:");
    io::stdin()
        .read_line(&mut plaintext)
        .expect("Failed to read line");

    return plaintext.trim().as_bytes().to_vec()
}

/*  
fn _encryption_demo() {
    let plaintext_bytes = read_input();
    let mode: ModeOfOperation = ModeOfOperation::prompt();
    println!("Plaintext bytes (hex): {:x?}", plaintext_bytes);

    let mut rng = rand::thread_rng();
    let mut k = [0u8; 32];
    rng.fill_bytes(&mut k);

    let mut nonce_or_iv = [0u8; 16];
    rng.fill_bytes(&mut nonce_or_iv);

    let ciphertext_bytes: Vec<u8> = mode.encrypt(&k, &nonce_or_iv, &plaintext_bytes)
                                            .expect("Encryption failed");
    println!("Ciphertext bytes (hex): {:x?}", ciphertext_bytes);

    let retrieved_plaintext: Vec<u8> = mode.decrypt(&k, &nonce_or_iv, &ciphertext_bytes)
                                                .expect("Decryption failed");
    println!("Retrieved plaintext bytes (hex): {:x?}", retrieved_plaintext);
}
*/
fn _main() {
    //exercise2();
    //encryption_demo();
}
