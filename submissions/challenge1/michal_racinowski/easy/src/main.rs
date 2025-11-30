use base64::prelude::*;
use easy::Aes128Cbc;
use std::ffi::{OsStr, OsString};

enum Cmd {
    Encrypt,
    Decrypt,
}

fn main() {
    let args: Vec<OsString> = std::env::args_os().collect();

    if args.len() != 5 {
        eprintln!("Usage: easy encrypt KEY IV FILE");
        return;
    }

    let cmd = if args[1] == OsStr::new("encrypt") {
        Cmd::Encrypt
    } else if args[1] == OsStr::new("decrypt") {
        Cmd::Decrypt
    } else {
        eprintln!("Invalid command {:?}", args[1]);
        return;
    };

    let key = &args[2];
    let iv = &args[3];
    let path = &args[4];

    let Ok(cipher) = Aes128Cbc::new(key.as_encoded_bytes(), iv.as_encoded_bytes()) else {
        eprintln!(
            "Invalid encryption parameters key: {:?} or iv: {:?}",
            key, iv
        );
        return;
    };

    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("Error reading the file {:?}: {}", path, e);
            return;
        }
    };

    match cmd {
        Cmd::Encrypt => {
            let ctx = cipher.encrypt(&bytes);

            println!("{}", BASE64_STANDARD.encode(ctx));
        }

        Cmd::Decrypt => {
            let clean: Vec<u8> = bytes
                .into_iter()
                .filter(|byte| base64::alphabet::STANDARD.as_str().contains(*byte as char))
                .collect();
            let ctx = BASE64_STANDARD.decode(clean).unwrap();

            let Some(ptx) = cipher.decrypt(&ctx) else {
                eprintln!("Invalid ciphertext");
                return;
            };

            if let Ok(string) = String::from_utf8(ptx.clone()) {
                println!("{}", string);
            } else {
                eprintln!("Warning: Invalid characters in the output");
                println!("{}", hex::encode(&ptx));
            }
        }
    }
}
