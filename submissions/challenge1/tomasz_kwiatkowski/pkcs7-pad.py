def pkcs7_pad(data: bytes, block_size: int) -> bytes:
    if block_size <= 0 or block_size >= 256:
        raise ValueError("block_size must be between 1 and 255")

    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len


if __name__ == "__main__":
    text = b"YELLOW SUBMARINE"
    padded = pkcs7_pad(text, 20)
    print(padded)
