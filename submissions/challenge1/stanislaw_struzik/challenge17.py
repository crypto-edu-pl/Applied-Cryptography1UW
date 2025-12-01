"""Challenge 17: The CBC padding oracle attack"""

import os
import base64
import random
from typing import Tuple

from Cryptodome.Cipher import AES

BLOCK_SIZE = 16

# The 10 strings from the challenge (base64 encoded)
CHALLENGE_STRINGS = [
    b"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
    b"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
    b"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
    b"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
    b"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
    b"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
    b"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
    b"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
    b"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
    b"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
]


def pad_pkcs7(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    """Apply PKCS#7 padding to data."""
    padding_len = block_size - (len(data) % block_size)
    return data + bytes([padding_len] * padding_len)


def unpad_pkcs7(data: bytes) -> bytes:
    """
    Remove and validate PKCS#7 padding.
    Raises ValueError if padding is invalid.
    """
    if not data:
        raise ValueError("Empty data")

    padding_len = data[-1]

    if padding_len == 0 or padding_len > BLOCK_SIZE:
        raise ValueError(f"Invalid padding length: {padding_len}")

    # Verify all padding bytes are correct
    for i in range(1, padding_len + 1):
        if data[-i] != padding_len:
            raise ValueError(f"Invalid padding byte at position -{i}")

    return data[:-padding_len]


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two byte strings of equal length."""
    return bytes(x ^ y for x, y in zip(a, b))


class PaddingOracle:
    """Simulates a server that encrypts/decrypts with AES-CBC and reveals padding validity."""

    def __init__(self):
        self.key = os.urandom(BLOCK_SIZE)

    def encrypt(self) -> Tuple[bytes, bytes]:
        """Select a random string, encrypt it with AES-CBC, return (ciphertext, iv)."""
        plaintext = base64.b64decode(random.choice(CHALLENGE_STRINGS))
        iv = os.urandom(BLOCK_SIZE)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad_pkcs7(plaintext))
        return ciphertext, iv

    def check_padding(self, ciphertext: bytes, iv: bytes) -> bool:
        """Decrypt and return True if padding is valid, False otherwise."""
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        plaintext = cipher.decrypt(ciphertext)
        try:
            unpad_pkcs7(plaintext)
            return True
        except ValueError:
            return False


def attack_block(
    target_block: bytes,
    prev_block: bytes,
    oracle: PaddingOracle
) -> bytes:
    """
    Decrypt a single block using the padding oracle attack.

    The attack works by manipulating the previous block (or IV) to control what
    the decrypted bytes XOR to. When we get valid padding, we can deduce the
    intermediate state and thus the plaintext.
    """
    # Intermediate state: result of AES block decryption before XOR with prev_block
    intermediate = bytearray(BLOCK_SIZE)
    # Our crafted "previous block" for manipulation
    crafted = bytearray(BLOCK_SIZE)

    # Work backwards from the last byte to the first
    for byte_pos in range(BLOCK_SIZE - 1, -1, -1):
        target_padding = BLOCK_SIZE - byte_pos

        # Set up bytes we've already discovered to produce target_padding
        for i in range(byte_pos + 1, BLOCK_SIZE):
            crafted[i] = intermediate[i] ^ target_padding

        # Try all 256 possible values for the current byte
        found = False
        for guess in range(256):
            crafted[byte_pos] = guess

            if oracle.check_padding(target_block, bytes(crafted)):
                # Verify not a false positive for the last byte
                if byte_pos == BLOCK_SIZE - 1:
                    test_crafted = bytearray(crafted)
                    test_crafted[byte_pos - 1] ^= 1
                    if not oracle.check_padding(target_block, bytes(test_crafted)):
                        continue

                intermediate[byte_pos] = guess ^ target_padding
                found = True
                break

        if not found:
            raise RuntimeError(f"Could not find valid byte at position {byte_pos}")

    return xor_bytes(bytes(intermediate), prev_block)


def padding_oracle_attack(
    ciphertext: bytes,
    iv: bytes,
    oracle: PaddingOracle
) -> bytes:
    """Perform a full padding oracle attack to decrypt the ciphertext."""
    # Split ciphertext into blocks
    blocks = [ciphertext[i:i + BLOCK_SIZE]
              for i in range(0, len(ciphertext), BLOCK_SIZE)]
    # Prepend IV as the "previous block" for the first real block
    all_blocks = [iv] + blocks

    # Decrypt each block
    plaintext = b''
    for i in range(1, len(all_blocks)):
        decrypted = attack_block(all_blocks[i], all_blocks[i - 1], oracle)
        plaintext += decrypted

    return unpad_pkcs7(plaintext)


def main():
    oracle = PaddingOracle()
    ciphertext, iv = oracle.encrypt()
    plaintext = padding_oracle_attack(ciphertext, iv, oracle)
    print(f"Decrypted: {plaintext.decode()}")


if __name__ == "__main__":
    main()
