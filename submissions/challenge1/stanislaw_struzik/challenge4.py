"""Challenge 4: Detect single-character XOR"""

import os
from typing import Tuple

from challenge3 import break_single_byte_xor


def detect_single_char_xor(lines: list[str]) -> Tuple[int, int, bytes, float]:
    """
    Find which line in the list has been encrypted with single-char XOR.

    Returns: (line_number, key, plaintext, score)
    """
    best_result = None
    best_line_num = 0
    best_overall_score = float('-inf')

    for line_num, hex_line in enumerate(lines):
        hex_line = hex_line.strip()
        if not hex_line:
            continue

        try:
            ciphertext = bytes.fromhex(hex_line)
        except ValueError:
            continue

        key, plaintext, score = break_single_byte_xor(ciphertext)

        if score > best_overall_score:
            best_overall_score = score
            best_line_num = line_num
            best_result = (key, plaintext, score)

    return best_line_num, best_result[0], best_result[1], best_result[2]


def main():
    data_file = os.path.join(os.path.dirname(__file__), "data", "4.txt")
    with open(data_file) as f:
        lines = f.readlines()
    line_num, key, plaintext, _ = detect_single_char_xor(lines)
    print(f"Line {line_num + 1}, Key: {chr(key)!r}, Plaintext: {plaintext.decode().strip()}")


if __name__ == "__main__":
    main()
