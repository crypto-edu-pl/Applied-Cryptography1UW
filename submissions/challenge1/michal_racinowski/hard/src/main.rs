//use base64::{Engine as _, engine::general_purpose::URL_SAFE};
use base64::prelude::*;
use easy::Aes128Cbc;
use hard::padding_oracle_attack;
use rand::{CryptoRng, Rng, SeedableRng, rngs::StdRng};

const BLOCK_SIZE: usize = 16;
const MESSAGES: [&str; 10] = [
    "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
    "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
    "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
    "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
    "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
    "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
    "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
    "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
    "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
    "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
];

#[allow(clippy::type_complexity)]
fn make_challenge(
    mut rng: impl Rng + CryptoRng + SeedableRng,
    ptx: &str,
) -> (Vec<u8>, Vec<u8>, impl Fn(&[u8], &[u8]) -> bool) {
    let key: [u8; BLOCK_SIZE] = rng.random();
    let iv: [u8; BLOCK_SIZE] = rng.random();

    let ctx = Aes128Cbc::new(&key, &iv).unwrap().encrypt(ptx.as_bytes());

    (iv.to_vec(), ctx, move |iv: &[u8], ctx: &[u8]| {
        if let Ok(c) = Aes128Cbc::new(&key, iv) {
            c.decrypt(ctx).is_some()
        } else {
            false
        }
    })
}

fn run_challenge(ptx: &str) {
    eprintln!("\x1b[1mOriginal plaintext:\x1b[0m \x1b[92m{:?}\x1b[0m", ptx);
    let (iv, ctx, oracle) = make_challenge(StdRng::from_os_rng(), ptx);
    eprintln!(
        "\x1b[1mCiphertext:\x1b[0m (\x1b[93m{}\x1b[0m, \x1b[93m{}\x1b[0m)",
        hex::encode(&iv),
        hex::encode(&ctx)
    );
    let out = padding_oracle_attack(&iv, &ctx, oracle).unwrap();

    println!("{}", String::from_utf8(out).unwrap());
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() == 2 {
        run_challenge(&args[1]);
        return;
    }

    for message in MESSAGES {
        let message = BASE64_STANDARD.decode(message).unwrap();
        let message = String::from_utf8(message).unwrap();
        run_challenge(&message);
    }
}
