"""Challenge 3: Single-byte XOR cipher"""

from typing import Tuple

# English letter frequencies
ENGLISH_FREQ = {
    'a': 8.2, 'b': 1.5, 'c': 2.8, 'd': 4.3, 'e': 12.7, 'f': 2.2,
    'g': 2.0, 'h': 6.1, 'i': 7.0, 'j': 0.15, 'k': 0.77, 'l': 4.0,
    'm': 2.4, 'n': 6.7, 'o': 7.5, 'p': 1.9, 'q': 0.095, 'r': 6.0,
    's': 6.3, 't': 9.1, 'u': 2.8, 'v': 0.98, 'w': 2.4, 'x': 0.15,
    'y': 2.0, 'z': 0.074, ' ': 13.0
}


def xor_single_byte(data: bytes, key: int) -> bytes:
    """XOR each byte in data with a single byte key."""
    return bytes(b ^ key for b in data)


def score_english(data: bytes) -> float:
    """
    Score how likely the data is to be English text.
    Higher score = more likely to be English.
    """
    score = 0.0
    for byte in data:
        char = chr(byte).lower()
        if char in ENGLISH_FREQ:
            score += ENGLISH_FREQ[char]
        elif chr(byte).isprintable():
            score += 0.5  # Small bonus for printable characters
        else:
            score -= 10.0  # Penalty for non-printable characters
    return score


def break_single_byte_xor(ciphertext: bytes) -> Tuple[int, bytes, float]:
    """
    Try all 256 possible single-byte XOR keys and return the best result.

    Returns: (key, plaintext, score)
    """
    best_score = float('-inf')
    best_key = 0
    best_plaintext = b''

    for key in range(256):
        plaintext = xor_single_byte(ciphertext, key)
        score = score_english(plaintext)

        if score > best_score:
            best_score = score
            best_key = key
            best_plaintext = plaintext

    return best_key, best_plaintext, best_score


def main():
    ciphertext = bytes.fromhex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
    key, plaintext, _ = break_single_byte_xor(ciphertext)
    print(f"Key: {chr(key)!r}, Plaintext: {plaintext.decode()}")


if __name__ == "__main__":
    main()
