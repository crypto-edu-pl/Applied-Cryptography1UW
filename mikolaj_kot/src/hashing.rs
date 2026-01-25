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

pub fn sha2(message: &[u8]) -> [u8; 32] {
    let mut buffer = message.to_vec();
    let ml: u64 = (message.len() as u64) * 8; // message length in bits 
    let mut hash_values: [u32; 8] = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ];
    let round_constats: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c48, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa11, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ];

    // Apply padding
    buffer.push(0x80);
    let rem = buffer.len() % 64;
    let pad_len = if rem <= 56 {
        56 - rem
    } else {
        64 + 56 - rem
    };
    buffer.extend(std::iter::repeat(0).take(pad_len));
    buffer.extend_from_slice(&ml.to_be_bytes());

    /* Now we have <<original message of length L> 1 <K zeros> <L as 64 bit integer>> */

    // Process the message in successive 512-bit chunks
    let mut w = [0u32; 64];
    for chunk in buffer.chunks(64) {
        for i in 0..16 {
            let j = i * 4;
            w[i] = (chunk[j] as u32) << 24 | 
                (chunk[j + 1] as u32) << 16 | 
                (chunk[j + 2] as u32) << 8 | 
                (chunk[j + 3] as u32);
        }

        // Perform word extension
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        // Initialise working variables
        let mut t: [u32; 8] = hash_values;
    
        // Main compression function
        for i in 0..64 {
            let s1 = t[4].rotate_right(6) ^ t[4].rotate_right(11) ^ t[4].rotate_right(25);
            let ch = (t[4] & t[5]) ^ ((!t[4]) & t[6]);
            let temp1 = t[7]
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(round_constats[i])
                .wrapping_add(w[i]);
            let s0 = t[0].rotate_right(2) ^ t[0].rotate_right(13) ^ t[0].rotate_right(22);
            let maj = (t[0] & t[1]) ^ (t[0] & t[2]) ^ (t[1] & t[2]);
            let temp2 = s0.wrapping_add(maj);

            // Update working variables
            t[7] = t[6];
            t[6] = t[5];
            t[5] = t[4];
            t[4] = t[3].wrapping_add(temp1);
            t[3] = t[2];
            t[2] = t[1];
            t[1] = t[0];
            t[0] = temp1.wrapping_add(temp2);
        }

        // Add the compressed chunk to the current hash value
        for i in 0..8 {
            hash_values[i] = hash_values[i].wrapping_add(t[i]);
        }
    }

    // Produce the final hash value (big-endian)
    hash_values.iter().fold([0u8; 32], |mut acc, &val| {
        let bytes = val.to_be_bytes();
        let start = acc.iter().position(|&x| x == 0).unwrap();
        acc[start..start + 4].copy_from_slice(&bytes);
        acc
    })
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
    assert_eq!(len_val, 120);
}