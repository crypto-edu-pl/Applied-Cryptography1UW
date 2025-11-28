use aes::Aes128;
use cipher::{BlockEncrypt, KeyInit};
use generic_array::GenericArray;

use image::{DynamicImage, GenericImageView, ImageBuffer, Rgba};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Load input image
    let img_path = "input.png";  // make sure this exists next to Cargo.toml
    let img = image::open(img_path)?;
    println!(
        "Loaded image {} ({}x{})",
        img_path,
        img.width(),
        img.height()
    );

    // 2. Convert to RGBA8 and extract raw pixel buffer
    let mut rgba: ImageBuffer<Rgba<u8>, Vec<u8>> = img.to_rgba8();
    let (_width, _height) = rgba.dimensions();

    // IMPORTANT: keep the FlatSamples in a binding so it lives long enough
    let mut flat = rgba.as_flat_samples_mut();
    let pixels: &mut [u8] = flat.as_mut_slice();

    // 3. AES-128 ECB encryption setup
    let key = [0u8; 16]; // fixed key for demo
    let cipher = Aes128::new(&GenericArray::from_slice(&key));

    // 4. Encrypt in ECB (block-by-block)
    for block in pixels.chunks_exact_mut(16) {
        let mut b = GenericArray::clone_from_slice(block);
        cipher.encrypt_block(&mut b);
        block.copy_from_slice(&b);
    }

    // 5. Save the encrypted image
    let out_path = "output.png";
    let out_img = DynamicImage::ImageRgba8(rgba);
    out_img.save(out_path)?;

    println!("Saved ECB-encrypted image to {}", out_path);
    println!("Open it to see the ECB block pattern leakage.");

    Ok(())
}

