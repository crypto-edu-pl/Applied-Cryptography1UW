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
