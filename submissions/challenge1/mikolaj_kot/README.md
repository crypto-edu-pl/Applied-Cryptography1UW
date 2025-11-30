# Cryptopals Solutions (Rust)

A "roll-your-own-crypto" library and CLI tool implementing solutions to the [Cryptopals Crypto Challenges](https://cryptopals.com/). This project demonstrates low-level cryptographic concepts including XOR ciphers, frequency analysis, and SHA-1 implementation from scratch.

## Getting Started

Ensure you have Rust and Cargo installed.

```bash
# Build the project
cargo build --release

# View help menu
cargo run -- --help
```

## Assignment Demos
To run specific challenge solutions, use the `demo` subcommand. The ID format is SXCY (Set X, Challenge Y).

### Recommended Demos for Evaluation

| Difficulty | ID | Description | Command |
| :--- | :--- | :--- | :--- |
| **Easy** | `S1C1` | Hex to Base64 Conversion | `cargo run -- demo s1c1` |
| **Medium** | `S1C4` | Detect Single-Byte XOR | `cargo run -- demo s1c4` |
| **Hard** | `S4C29`| SHA-1 Length Extension Attack | `cargo run -- demo s4c29` |

### Listing all demos

To see all implemented challenges:
```bash
cargo run -- demo --list  # (Or just use --help on the demo subcommand)
```
