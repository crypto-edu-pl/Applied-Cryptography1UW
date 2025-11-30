use block_ciphers::{
    blocks::AesBlocks, cbc::CbcEncryptedBlocks, padding_oracle::oracle::PaddingOracle,
    pkcs7::unpad_mut,
};

pub fn main() {
    let oracle = PaddingOracle::new(false);

    // We get an encrypted message with unknown key that we want to decrypt.
    let encrypted_message = oracle.get_encrypted_message();

    let plaintext = break_message(&oracle, &encrypted_message);

    let string = String::from_utf8(plaintext).unwrap();

    println!("Plaintext: {string}");
}

fn break_message(oracle: &PaddingOracle, encrypted_message: &CbcEncryptedBlocks) -> Vec<u8> {
    let mut full_message = encrypted_message.to_full_message();
    let mut plaintext = Vec::new();

    // We start by decrypting the last block, which requires modifying 2nd last block that directly affects decrypted last block via xor.
    for current_block in (1..full_message.block_count()).rev() {
        let unmodified_full_message = full_message.clone();
        // We start with the last byte and work our way back to the first byte.
        for current_byte in (0..=15).rev() {
            let search_value = 16 - current_byte as u8;

            // We obtain the value of the current byte in the plaintext.
            let byte_value =
                break_byte(oracle, &mut full_message, current_block, current_byte).unwrap();
            plaintext.push(byte_value);

            // step 1: We modify `current_byte`-th last byte from value `byte_value` to `search_value + 1` (which is next padding that we will check)
            // E.g. if we broke ** ** ** xx 04 04 04 04 (8 bytes for simplicity) and know that x is 0xb3,
            // we need to xor it with 0xb3 ^ 0x05, so that it becomes 0x05
            *full_message
                .get_byte(current_block - 1, current_byte)
                .unwrap() ^= byte_value ^ (search_value + 1);

            // step 2: We increment other padding bytes by one, so for the example above:
            // before step 1: ** ** ** xx 04 04 04 04
            // after step 1 : ** ** ** 05 04 04 04 04
            // after step 2 : ** ** ** 05 05 05 05 05
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

    // To find `current_byte`-th last byte in the plaintext, we need to find a byte `byte` such that:
    for byte in 0..=255 {
        // Modify the byte in question until we find a valid padding, which can tell us what the value at that byte is.
        *full_message
            .get_byte(current_block - 1, current_byte)
            .unwrap() ^= byte;

        if oracle.is_padding_valid(&CbcEncryptedBlocks::from_full_message(full_message)) {
            if current_byte != 15 {
                result = Some(byte ^ search_value);
            } else {
                // In case of breaking the last byte, it could be the case that we got "lucky"
                // and didn't get padding of length 1, but rather something longer,
                // so we would get multiple valid answers.
                // To filter those cases, we can just change 2nd last byte and make sure that padding is still valid.
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
        // Undo the modification, so that the message is untouched.
        *full_message
            .get_byte(current_block - 1, current_byte)
            .unwrap() ^= byte;

        if result.is_some() {
            return result;
        }
    }
    None
}
