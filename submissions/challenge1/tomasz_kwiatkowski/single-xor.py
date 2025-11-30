import urllib.request


ENGLISH_FREQ = {
    'E': 12.70, 'T': 9.06, 'A': 8.17, 'O': 7.51, 'I': 6.97, 'N': 6.75,
    'S': 6.33, 'H': 6.09, 'R': 5.99, 'D': 4.25, 'L': 4.03, 'C': 2.78,
    'U': 2.76, 'M': 2.41, 'W': 2.36, 'F': 2.23, 'G': 2.02, 'Y': 1.97,
    'P': 1.93, 'B': 1.49, 'V': 0.98, 'K': 0.77, 'J': 0.15, 'X': 0.15,
    'Q': 0.10, 'Z': 0.07, ' ': 13.0
}


def english_score(s: bytes) -> float:
    score = 0.0
    for b in s.upper():
        if 32 <= b <= 126:
            score += ENGLISH_FREQ.get(chr(b), 0)
        else:
            score -= 50
    return score


def xor(data: bytes, key: int) -> bytes:
    return bytes([b ^ key for b in data])


def break_single_byte_xor(hexstr: str):
    data = bytes.fromhex(hexstr)
    best = (float('-inf'), None, None)

    for k in range(256):
        pt = xor(data, k)
        s = english_score(pt)
        if s > best[0]:
            best = (s, k, pt)

    return best


if __name__ == "__main__":
    url = "https://cryptopals.com/static/challenge-data/4.txt"
    with urllib.request.urlopen(url) as resp:
        text = resp.read().decode('utf-8')

    best_overall = (float('-inf'), None, None, None)
    for lineno, line in enumerate(text.splitlines(), start=1):
        score, key, pt = break_single_byte_xor(line)
        if score > best_overall[0]:
            best_overall = (score, lineno, key, pt)

    _, line_no, key, plaintext = best_overall
    print("Probably encrypted line:", line_no)
    print("Key (byte):", hex(key))
    print("Decoded plaintext:", plaintext.decode('utf-8', errors='replace'))
