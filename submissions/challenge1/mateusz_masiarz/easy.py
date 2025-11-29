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
