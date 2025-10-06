use std::io;

/// Encrypt or decrypt one block (bitwise Caesar = XOR version)
fn xor_block(block: &[u8], key: u8) -> Vec<u8> {
    block.iter().map(|&b| b ^ key).collect()
}

fn main() {
    println!("=== Bitwise Caesar (key-per-block) ===");

    // Read plaintext
    let mut plaintext = String::new();
    println!("Enter plaintext:");
    io::stdin().read_line(&mut plaintext).expect("Failed to read input");
    let plaintext = plaintext.trim().as_bytes();

    // Read number of blocks
    let mut num_blocks_input = String::new();
    println!("Enter number of blocks:");
    io::stdin().read_line(&mut num_blocks_input).expect("Failed to read input");
    let num_blocks: usize = num_blocks_input.trim().parse().expect("Enter a valid number");

    // Compute block size (approx equal division)
    let block_size = (plaintext.len() + num_blocks - 1) / num_blocks;

    // Split plaintext into blocks
    let blocks: Vec<&[u8]> = plaintext.chunks(block_size).collect();

    // Collect keys for each block
    let mut keys: Vec<u8> = Vec::new();
    for i in 0..num_blocks {
        let mut key_input = String::new();
        println!("Enter numeric key for block {} (0–255):", i + 1);
        io::stdin().read_line(&mut key_input).expect("Failed to read key");
        let key: u8 = key_input.trim().parse().expect("Enter an integer between 0 and 255");
        keys.push(key);
    }

    // Encrypt
    let mut ciphertext: Vec<u8> = Vec::new();
    for (i, block) in blocks.iter().enumerate() {
        let key = keys[i];
        ciphertext.extend(xor_block(block, key));
    }

    println!("\nEncrypted (hex): {:02X?}", ciphertext);

    // Decrypt
    let mut decrypted: Vec<u8> = Vec::new();
    let mut offset = 0;
    for (i, _) in blocks.iter().enumerate() {
        let key = keys[i];
        let end = usize::min(offset + block_size, ciphertext.len());
        let decrypted_block = xor_block(&ciphertext[offset..end], key);
        decrypted.extend(decrypted_block);
        offset += block_size;
    }

    let decrypted_text = String::from_utf8_lossy(&decrypted);
    println!("Decrypted text: {}", decrypted_text);
}
