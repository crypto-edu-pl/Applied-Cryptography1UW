use ed25519_dalek::{Signer, Verifier, SigningKey, VerifyingKey, Signature};
use rand::rngs::OsRng;
use hex;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = OsRng;
    let signing_key = SigningKey::generate(&mut rng); // private key s
    let verify_key: VerifyingKey = signing_key.verifying_key(); // public key v
  
        let m = b"This is from me, Alice!";
    let sigma: Signature = signing_key.sign(m);

    // Bob verifies original message
    match verify_key.verify(m, &sigma) {
        Ok(_) => {
            println!(
                "\n--- Verification Attempt 1 ---\n\
                 Bob receives the message:\n  \"{}\"\n\
                 with signature:\n  {}\n\
                 The signature of the message is VERIFIED \n",
                String::from_utf8_lossy(m),
                hex::encode(sigma.to_bytes())
            );
        }
        Err(_) => {
            println!(
                "\n--- Verification Attempt 1 ---\n\
                 Bob receives the message:\n  \"{}\"\n\
                 with signature:\n  {}\n\
                  The signature of the message is NOT verified!",
                String::from_utf8_lossy(m),
                hex::encode(sigma.to_bytes())
            );
        }
    }

    // Now try with tampered message
    let tampered = b"This is from me, Eve!";
    match verify_key.verify(tampered, &sigma) {
        Ok(_) => {
            println!(
                "\n--- Verification Attempt 2 (Tampered) ---\n\
                 Bob receives the message:\n  \"{}\"\n\
                 with signature:\n  {}\n\
                 The signature of the message is VERIFIED\n",
                String::from_utf8_lossy(tampered),
                hex::encode(sigma.to_bytes())
            );
        }
        Err(_) => {
            println!(
                "\n--- Verification Attempt 2 (Tampered) ---\n\
                 Bob receives the message:\n  \"{}\"\n\
                 with signature:\n  {}\n\
                 The signature of the message is NOT verified \n",
                String::from_utf8_lossy(tampered),
                hex::encode(sigma.to_bytes())
            );
        }
    }


    Ok(())
}
