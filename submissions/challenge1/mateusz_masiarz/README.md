Running: `python3 {easy,medium,hard}.py`

# Easy (3. Single-byte XOR cipher)

Check every byte value as potential key and use frequency analysis to find the best one.

```python
def easy__single_byte_xor_cipher(input):
    import string

    b = bytes.fromhex(input)

    def calc_score(s):
        freq = {
            'a': 0.08167, 'b': 0.01492, 'c': 0.02782, 'd': 0.04253,
            'e': 0.12702, 'f': 0.02228, 'g': 0.02015, 'h': 0.06094,
            'i': 0.06966, 'j': 0.00153, 'k': 0.00772, 'l': 0.04025,
            'm': 0.02406, 'n': 0.06749, 'o': 0.07507, 'p': 0.01929,
            'q': 0.00095, 'r': 0.05987, 's': 0.06327, 't': 0.09056,
            'u': 0.02758, 'v': 0.00978, 'w': 0.02360, 'x': 0.00150,
            'y': 0.01974, 'z': 0.00074, ' ': 0.13000
        }
        score = 0
        for char in s:
            score += freq.get(chr(char), 0)
        return score

    best_score = 0
    best_str = ""
    byte = 0
    # Check every byte
    for i in range(256):
        new_bytes = [byte ^ i for byte in b]
        if all(chr(byte) in string.printable for byte in new_bytes):
            score = calc_score(new_bytes)
            if score > best_score:
                best_score = score
                best_str = ''.join(map(chr, new_bytes))
                byte = i

    return best_str, best_score, byte

result, _, byte = easy__single_byte_xor_cipher("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
print(result)
print(f"key: {chr(byte)}")
```
Answer: Cooking MC's like a pound of bacon
Key: X

# Medium (4. Detect single-character XOR)

Use the previous function on each line and find the best result.

```python
def medium__detect_single_character_xor(lines):
    best_score = 0
    best_str = ""
    byte = 0

    for line in lines:
        str, score, b = easy__single_byte_xor_cipher(line)
        if score > best_score:
            best_score = score
            best_str = str
            byte = b

    print(best_str)
    print(f"key: {chr(byte)}")


medium__detect_single_character_xor(open("4.txt").readlines())
```

Answer: Now that the party is jumping\n
Key: '5'


# Hard (14. Byte-at-a-time ECB decryption (Harder))

```python
import os, base64

from Crypto.Util.Padding import pad
from Crypto.Cipher import AES

def encrypt_ecb(input, key):
    cipher = AES.new(key, AES.MODE_ECB)
    padded_input = pad(input, AES.block_size)
    return cipher.encrypt(padded_input)


def detect(ciphertext, block_size):
    """
    If any two blocks in ciphertext repeat, its ECB
    """
    blocks = [ciphertext[i:i + block_size] for i in range(0, len(ciphertext), block_size)]
    num_unique_blocks = len(set(blocks))
    num_total_blocks = len(blocks)

    if num_unique_blocks < num_total_blocks:
        return "ECB"
    else:
        return "CBC"


# Random padding
random_bytes = os.urandom(os.urandom(1)[0] % 32 + 5)
# Random encryption key
key = os.urandom(16)
def harder_oracle(input):
    unknown_string = (
        "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
        "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
        "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
        "YnkK"
    )
    unknown_bytes = base64.b64decode(unknown_string)
    input_bytes = random_bytes + input + unknown_bytes
    return encrypt_ecb(input_bytes, key)


def detect_block_size(oracle):
    """
    Find block size by looking for increase in ciphertext length as we increase input length
    """
    input = b""
    initial_length = len(oracle(input))

    i = 1
    while True:
        input += b"A"
        new_length = len(oracle(input))
        if new_length > initial_length:
            return new_length - initial_length
        i += 1


def calculate_prefix_len(oracle, block_size):
    """
    Find length of random prefix added by oracle, by looking for first occurrence of
    two identical, consecutive blocks in the ciphertext and calculating from that the
    length of the prefix.
    """
    for n in range(1000):
        input = b"A" * n
        ciphertext = oracle(input)

        blocks = [ciphertext[i:i + block_size] for i in range(0, len(ciphertext), block_size)]
        for i in range(len(blocks) - 1):
            if blocks[i] == blocks[i + 1]:
                # We found two identical, consecutive blocks, so our input ends at the end of block i+1.
                # So there were (i - 1) full blocks of random prefix and block_size - (n % block_size)
                # bytes of random prefix in block i.
                return block_size - (n % block_size) + (i - 1) * block_size
    raise


def find_secret_len(oracle, prefix_len):
    """
    Find length of unknown string appended by oracle, by looking for increase
    in ciphertext length as we increase input length. The first i where the
    length increases tells us the length of the padding used in the empty input case.
    """
    input = b""
    initial_length = len(oracle(input))

    i = 1
    while True:
        input += b"A"
        new_length = len(oracle(input))
        if new_length > initial_length:
            # Calculate secret length by subtracting padding len i and random prefix len
            # from initial length
            return initial_length - i - prefix_len
        i += 1


def find_unknown_key(oracle):
    block_size = detect_block_size(oracle)
    print(f"Detected block size: {block_size}")

    input = b"A" * (block_size * 10) # for safety
    ciphertext = oracle(input)

    if detect(ciphertext, block_size) != "ECB":
        raise Exception("Oracle is not using ECB mode")

    prefix_len = calculate_prefix_len(oracle, block_size)
    # Number of full blocks occupied by random prefix
    random_blocks = prefix_len // block_size + 1
    secret_len = find_secret_len(oracle, prefix_len)
    unknown_bytes = b""

    for i in range(0, secret_len):
        block_num = random_blocks + i // block_size
        # Number of bytes to pad so that the byte we want to guess is at the end of a block
        prefix_size = block_size - 1 - (i % block_size)
        padding_for_random = (block_size - (prefix_len % block_size)) * b"A"

        dictionary = {}
        for b in range(256):
            # Align random prefix to block boundary, then add padding, then known bytes, then byte to guess
            input = padding_for_random + \
                    b"A" * prefix_size + \
                    unknown_bytes + \
                    bytes([b])

            cipher = oracle(input)
            dictionary[cipher[(block_num * block_size):(block_num * block_size + block_size)]] = b

        # Pad random prefix, then padding to align byte to guess
        cipher = oracle(padding_for_random + b"A" * prefix_size)
        b = dictionary[cipher[(block_num * block_size):(block_num * block_size + block_size)]]
        unknown_bytes += bytes([b])

    print(unknown_bytes)


find_unknown_key(harder_oracle)
```

Answer: "Rollin' in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies on standby waving just to say hi\nDid you stop? No, I just drove by\n"
