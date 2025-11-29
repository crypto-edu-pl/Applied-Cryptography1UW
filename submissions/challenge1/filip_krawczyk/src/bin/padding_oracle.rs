use block_ciphers::{
    blocks::AesBlocks, cbc::CbcEncryptedBlocks, padding_oracle::oracle::PaddingOracle,
    pkcs7::unpad_mut,
};

pub fn main() {
    let oracle = PaddingOracle::new(false);

    let encrypted_message = oracle.get_encrypted_message();

    let plaintext = break_message(&oracle, &encrypted_message);

    let string = String::from_utf8(plaintext).unwrap();

    println!("Plaintext: {string}");
}

fn break_message(oracle: &PaddingOracle, encrypted_message: &CbcEncryptedBlocks) -> Vec<u8> {
    let mut full_message = encrypted_message.to_full_message();
    let mut plaintext = Vec::new();

    for current_block in (1..full_message.block_count()).rev() {
        let unmodified_full_message = full_message.clone();
        for current_byte in (0..=15).rev() {
            let search_value = 16 - current_byte as u8;

            let x = break_byte(oracle, &mut full_message, current_block, current_byte).unwrap();
            plaintext.push(x);

            *full_message
                .get_byte(current_block - 1, current_byte)
                .unwrap() ^= x ^ (search_value + 1);

            for i in current_byte + 1..=15 {
                *full_message.get_byte(current_block - 1, i).unwrap() ^=
                    search_value ^ (search_value + 1);
            }
        }
        full_message = unmodified_full_message;
        full_message.pop_block().unwrap();
    }

    plaintext.reverse();
    unpad_mut(&mut plaintext, 16).unwrap();
    plaintext
}

fn break_byte(
    oracle: &PaddingOracle,
    full_message: &mut AesBlocks,
    current_block: usize,
    current_byte: usize,
) -> Option<u8> {
    let search_value = 16 - current_byte as u8;
    let mut result = None;

    for byte in 0..=255 {
        *full_message
            .get_byte(current_block - 1, current_byte)
            .unwrap() ^= byte;

        if oracle.is_padding_valid(&CbcEncryptedBlocks::from_full_message(full_message)) {
            if current_byte == 0 {
                result = Some(byte ^ search_value);
            } else {
                // We know that padding is correct, but it might either be what we are looking for
                // or by accident we got a longer correct padding.
                *full_message
                    .get_byte(current_block - 1, current_byte - 1)
                    .unwrap() ^= 1;
                if oracle.is_padding_valid(&CbcEncryptedBlocks::from_full_message(full_message)) {
                    result = Some(byte ^ search_value);
                }
                *full_message
                    .get_byte(current_block - 1, current_byte - 1)
                    .unwrap() ^= 1;
            }
        }
        *full_message
            .get_byte(current_block - 1, current_byte)
            .unwrap() ^= byte;

        if result.is_some() {
            return result;
        }
    }
    None
}
