use block_ciphers::{
    bit_flipping::{cookie::encode_userdata, server::Server},
    cbc::CbcEncryptedBlocks,
    iv::Iv,
};

fn xor_arrays(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b.iter()).map(|(a, b)| a ^ b).collect()
}

pub fn main() {
    let server = Server::new();

    // We want to construct a cookie like this:
    // admin=true;x=aaa%20MCs;userdata=;comment2=%20like%20a%20pound%20of%20bacon
    // ^^^^^^^^^^^^^^^^----------------^^^^^^^^^^^^^^^^----------------^^^^^^^^^^^^^^^^

    // But we have for example:
    // comment1=cooking%20MCs;userdata=;comment2=%20like%20a%20pound%20of%20bacon
    // ^^^^^^^^^^^^^^^^----------------^^^^^^^^^^^^^^^^----------------^^^^^^^^^^^^^^^^

    let encrypted_cookie = server.get_encrypted_cookie_for_user("");

    // We assume that encoding algorithm is known, so that we know exactly one (plaintext, ciphertext) pair.
    let my_encoded_data = encode_userdata("");

    // Compute the data in the first block in the encoded plaintext.
    let first_block_data = my_encoded_data.as_bytes()[0..16].to_owned();

    // We want to modify that first block to this value:
    let desired_first_block_data = "admin=true;x=aaa".as_bytes().to_owned();

    // Compute what value IV should be set to in order to change the first block to the desired value.
    let desired_cookie_xor = xor_arrays(&first_block_data, &desired_first_block_data);
    let new_iv = Iv::new_unchecked(
        xor_arrays(encrypted_cookie.iv.get(), &desired_cookie_xor)
            .try_into()
            .unwrap(),
    );

    let crafted_cookie = CbcEncryptedBlocks {
        iv: new_iv,
        ciphertext: encrypted_cookie.ciphertext.clone(),
    };

    let is_admin_normal = server.is_admin(&encrypted_cookie).unwrap();
    println!("Is admin normal: {is_admin_normal}");
    let is_admin_crafted = server.is_admin(&crafted_cookie).unwrap();
    println!("Is admin crafted: {is_admin_crafted}");
}
