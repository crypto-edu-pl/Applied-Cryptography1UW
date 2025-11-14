// Demonstration that a linear "CRC-MAC" is completely insecure.
// MAC_k(m) = CRC(k || m), with CRC being just XOR of all bytes.

fn toy_crc(data: &[u8]) -> u8 {
    // Extremely simple linear checksum: XOR of all bytes
    data.iter().fold(0u8, |acc, &b| acc ^ b)
}

fn crc_mac(key: &[u8], msg: &[u8]) -> u8 {
    let mut buf = Vec::with_capacity(key.len() + msg.len());
    buf.extend_from_slice(key);
    buf.extend_from_slice(msg);
    toy_crc(&buf)
}

// Attacker's forgery algorithm:
//
// Given:
//   - m0: message we queried
//   - tag0 = MAC_k(m0): tag we received from the oracle
//   - m1: *any* other message of the same length
//
// Compute a valid tag for m1 without knowing k.
fn forge_tag(m0: &[u8], tag0: u8, m1: &[u8]) -> u8 {
    assert_eq!(m0.len(), m1.len(), "attack needs equal-length messages");

    // Compute delta = m0 XOR m1
    let delta: Vec<u8> = m0.iter()
        .zip(m1.iter())
        .map(|(&a, &b)| a ^ b)
        .collect();

    // By linearity:
    // CRC(k || m1) = CRC(k || m0) XOR CRC(m0 XOR m1)
    //              = tag0         XOR CRC(delta)
    tag0 ^ toy_crc(&delta)
}

fn main() {
    // Secret key known only to the MAC oracle
    let key = b"supersecret";

    // Attacker chooses some m0 and asks the oracle for its MAC.
    let m0 = b"I love you"; // length 8
    let tag0 = crc_mac(key, m0);
    println!("Legit tag for m0    = {:?}: 0x{:02x}", String::from_utf8_lossy(m0), tag0);

    // Now attacker wants a tag for a *different* message m1 of same length.
    let m1 = b"I hate you"; // also length 8

    // Forge tag without knowing key:
    let forged_tag = forge_tag(m0, tag0, m1);
    println!("Forged tag for m1   = {:?}: 0x{:02x}", String::from_utf8_lossy(m1), forged_tag);

    // Check: does the verifier (who knows the key) accept this forged tag?
    let real_tag = crc_mac(key, m1);
    println!("Real tag for m1     = 0x{:02x}", real_tag);

    if forged_tag == real_tag {
        println!("Forgery succeeded: forged_tag == real_tag");
    } else {
        println!("Forgery failed (something is wrong)");
    }
}
