use beast_attack::oracle::Oracle;

pub fn main() {
    let key = [97_u8; 16];
    let iv = [97_u8; 16];
    let mut oracle = Oracle::new(key, iv, "supersecret");

    let ciphertext = oracle.encrypt("userdata");
    println!("{}", hex::encode(ciphertext));
}
