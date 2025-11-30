### Selected challenges

I chose the following challenges:

-   [9. Implement PKCS#7 padding](https://cryptopals.com/sets/2/challenges/9) (easy)
-   [10. CBC mode encryption](https://cryptopals.com/sets/2/challenges/10) (easy)
-   [16. CBC bitflipping attack](https://cryptopals.com/sets/2/challenges/16) (medium)
-   [17. CBC padding oracle attack](https://cryptopals.com/sets/3/challenges/17) (hard)

## Solutions Overview

1. **PKCS#7 Padding**: Implementation of the PKCS#7 padding scheme for block ciphers, including both padding and unpadding operations with validation.

2. **CBC Mode**: Implementation of Cipher Block Chaining (CBC) mode for AES-128, including encryption and decryption with initialization vectors.

3. **CBC Bit-Flipping Attack**: Demonstration of how to manipulate CBC-encrypted cookies by flipping bits in the IV to inject malicious content (e.g., `admin=true`).

4. **CBC Padding Oracle Attack**: Implementation of a padding oracle attack that decrypts CBC-encrypted messages without knowing the key, by exploiting padding validation errors.

All details are in the code and comments.

## How to Run

### Prerequisites

This project requires Rust and Cargo. Install them from [rustup.rs](https://rustup.rs/) if needed.

### Running the Bit-Flipping Attack

Run the CBC bit-flipping attack demonstration:

```bash
cargo run --bin bit_flipping
```

### Running the Padding Oracle Attack

Run the CBC padding oracle attack:

```bash
cargo run --bin padding_oracle
```

### Running tests for PKCS#7 and CBC

```bash
cargo test
```

## File Structure

### Core Library Files

-   **[`src/aes.rs`](./src/aes.rs)**: AES-128 block cipher operations. Provides functions to encrypt and decrypt individual 16-byte blocks using AES-128. It is a thin wrapper around the `aes` crate with better interface.

-   **[`src/blocks.rs`](./src/blocks.rs)**: Generic block data structure (`Blocks<BLOCK_SIZE_BYTES>`) that ensures data length is always a multiple of the block size. Provides utilities for block manipulation and iteration.

-   **[`src/pkcs7.rs`](./src/pkcs7.rs)**: PKCS#7 padding implementation. Contains:

    -   [`pad_mut()`](./src/pkcs7.rs#L7) / [`pad()`](./src/pkcs7.rs#L13): Adds PKCS#7 padding to data
    -   [`unpad_mut()`](./src/pkcs7.rs#L20) / [`unpad()`](./src/pkcs7.rs#L46): Removes and validates PKCS#7 padding
    -   Many [tests](./src/pkcs7.rs#L59) for standard inputs and edge cases

-   **[`src/cbc.rs`](./src/cbc.rs)**: CBC mode implementation for AES-128. Provides:
    -   [`encrypt()`](./src/cbc.rs#L37): Encrypts plaintext blocks using CBC mode
    -   [`decrypt()`](./src/cbc.rs#L52): Decrypts ciphertext blocks using CBC mode
    -   Many [tests](./src/cbc.rs#L73) for various number of blocks

### Bit-Flipping Attack

-   **[`src/bit_flipping/cookie.rs`](./src/bit_flipping/cookie.rs)**: Cookie encoding and parsing utilities. Implements URL encoding/decoding for cookie values and parsing of cookie strings into key-value pairs.

-   **[`src/bit_flipping/server.rs`](./src/bit_flipping/server.rs)**: Server simulation that:

    -   [`encrypt()`](./src/bit_flipping/server.rs#L26): Encrypts user cookies using CBC mode
    -   [`is_admin()`](./src/bit_flipping/server.rs#L33): Validates cookies and checks for admin privileges

-   **[`src/bin/bit_flipping.rs`](./src/bin/bit_flipping.rs)**: Executable that demonstrates the CBC bit-flipping attack. Shows how to manipulate the IV to inject `admin=true` into an encrypted cookie.

### Padding Oracle Attack

-   **[`src/padding_oracle/oracle.rs`](./src/padding_oracle/oracle.rs)**: Padding oracle implementation that:

    -   [`get_encrypted_message()`](./src/padding_oracle/oracle.rs#L19): Encrypts a secret message using CBC mode
    -   [`is_padding_valid()`](./src/padding_oracle/oracle.rs#L35): Provides an oracle function that reveals whether padding is valid
    -   Simulates a vulnerable server that leaks padding validation errors

-   **[`src/bin/padding_oracle.rs`](./src/bin/padding_oracle.rs)**: Executable that performs the padding oracle attack. Decrypts the secret message by exploiting the padding oracle, byte by byte.
