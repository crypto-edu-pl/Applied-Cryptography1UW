# Cryptopals Solutions (Rust)

A "roll-your-own-crypto" library and CLI tool implementing solutions to the [Cryptopals Crypto Challenges](https://cryptopals.com/). This project demonstrates low-level cryptographic concepts including XOR ciphers, frequency analysis, and SHA-1 implementation from scratch.

## Getting Started

Firstly, ensure you have Rust and Cargo installed.

```bash
# Build the project
cargo build --release

# View help menu
cargo run -- --help
```

## Assignment Demos

To run specific challenge solutions, use the `demo` subcommand. The ID format is sXcY (set X, challenge Y).

To view the code, open the *demo.rs* file and search for the challenge number you'd like to review.

### Recommended Demos for Evaluation

#### Coding Challenge #1

| Difficulty | ID | Description | Command |
| :--- | :--- | :--- | :--- |
| **Easy** | `s1c1` | Hex to Base64 Conversion | `cargo run -- demo s1c1` |
| **Medium** | `s1c4` | Detect Single-Byte XOR | `cargo run -- demo s1c4` |
| **Hard** | `s4c29`| SHA-1 Length Extension Attack | `cargo run -- demo s4c29` |

#### Coding Challenge #2

| Difficulty | ID | Description | Theme | Command |
| :--- | :--- | :--- | :--- | :--- |
| **Easy** | `s5c33` | Diffie-Hellman Implementation | symmetric key derivation | `cargo run -- demo s5c33` |
| **Medium** | `s5c36` | SRP Implementation | symmetric key derivation, key management, hmac-based authentication | `cargo run -- demo s5c36` |
| **Hard** | `s5c40`| E=3 RSA Broadcast Attack | asymmetric encryption | `cargo run -- demo s5c40` |

**Note:** These challenges have descriptions in the *demo.rs* file. This includes the explanation of HMAC for message authentication.

### Listing all demos

To see all implemented challenges:
```bash
cargo run -- demo --help 
```

### Notes

I tried to make this code extendible so that I can easily update it with solutions to other challenges in the future. The code is still not properly commented, some of the values used should be randomised etc. But the challenges are solved and some functionality for custom usage has been added.