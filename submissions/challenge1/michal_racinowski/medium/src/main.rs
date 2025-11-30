use easy::Aes128Cbc;
use medium::cbc_bit_flipping_attack;
use rand::{CryptoRng, Rng, SeedableRng, rngs::StdRng};

const BLOCK_SIZE: usize = 16;
const PREFIX: &[u8] = "comment1=cooking%20MCs;userdata=".as_bytes();
const TARGET: &[u8] = ";admin=true;x=y;".as_bytes();
const SUFFIX: &[u8] = ";comment2=%20like%20a%20pound%20of%20bacon".as_bytes();

#[allow(clippy::type_complexity)]
fn make_challenge(
    mut rng: impl Rng + CryptoRng + SeedableRng + 'static,
) -> (
    impl FnMut(&[u8]) -> Option<(Vec<u8>, Vec<u8>)>,
    impl Fn(&[u8], &[u8]) -> bool,
) {
    let key: [u8; BLOCK_SIZE] = rng.random();

    (
        move |input: &[u8]| {
            println!(
                "\x1b[1mReceived userdata:\x1b[0m (\x1b[93m{}\x1b[0m)",
                hex::encode(input)
            );

            for byte in input {
                if *byte == 0x3b || *byte == 0x3d {
                    // ';' / '='
                    return None;
                }
            }

            let mut ptx: Vec<u8> = PREFIX.to_vec();
            ptx.extend_from_slice(input);
            ptx.extend_from_slice(SUFFIX);

            println!(
                "\x1b[1mGenerated token:\x1b[0m \x1b[93m{}\x1b[0m",
                hex::encode(&ptx)
            );
            if let Ok(string) = String::from_utf8(ptx.clone()) {
                println!("\x1b[1mDecoded token:\x1b[0m \x1b[93m{}\x1b[0m", string);
            }

            let iv: [u8; BLOCK_SIZE] = rng.random();

            Some((
                iv.to_vec(),
                Aes128Cbc::new(&key, &iv).unwrap().encrypt(&ptx),
            ))
        },
        move |iv: &[u8], ctx: &[u8]| {
            println!(
                "\x1b[1mReceived (encrypted) token:\x1b[0m (\x1b[93m{}\x1b[0m, \x1b[93m{}\x1b[0m)",
                hex::encode(iv),
                hex::encode(ctx)
            );

            let Ok(c) = Aes128Cbc::new(&key, iv) else {
                println!("\x1b[1mInvalid IV\x1b[0m");
                return false;
            };

            let Some(mut ptx) = c.decrypt(ctx) else {
                println!("\x1b[1mInvalid padding\x1b[0m");
                return false;
            };

            for byte in &mut ptx {
                if *byte < 32 || *byte > 127 {
                    *byte = 0x3f; // '?'
                }
            }

            let ptx = String::from_utf8(ptx).unwrap();

            println!("\x1b[1mDecrypted token: \x1b[0m\x1b[93m{:?}\x1b[0m", ptx);

            ptx.contains(";admin=true;")
        },
    )
}

fn main() {
    let (oracle, evaluator) = make_challenge(StdRng::from_os_rng());

    let (iv, ctx) = cbc_bit_flipping_attack(PREFIX, SUFFIX, TARGET, oracle).unwrap();

    if evaluator(&iv, &ctx) {
        println!("\x1b[92mCookies contain \";admin=true;\"\x1b[0m");
        println!("\x1b[92;1mAdmin access granted!\"\x1b[0m");
    } else {
        println!("\x1b[91;1mStill a guest, better luck next time!\"\x1b[0m");
    }
}
