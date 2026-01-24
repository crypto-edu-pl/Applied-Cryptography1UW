SESSION_ID = "TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE="

def format_request(P: str) -> str:
    return (
        "POST / HTTP/1.1\r\n"
        "Host: hapless.com\r\n"
        f"Cookie: sessionid={SESSION_ID}\r\n"
        f"Content-Length: {len(P)}\r\n"
        "\r\n"
        f"{P}"
    )


def compress(data: bytes) -> bytes:
    import zlib

    return zlib.compress(data, level=9)


def build_pad_source(length: int = 4096) -> str:
    # Deterministic pad that doesn't compress well.
    seed = 1
    chars = []
    for _ in range(length):
        seed = (1103515245 * seed + 12345) & 0x7FFFFFFF
        chars.append(chr(32 + (seed % 95)))
    return "".join(chars)


PAD_SOURCE = build_pad_source()


def make_pad(length: int) -> str:
    return PAD_SOURCE[:length]


def encrypt_stream(data: bytes) -> bytes:
    from Crypto.Cipher import AES
    import os

    key = os.urandom(16)
    nonce = os.urandom(8)
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    return nonce + cipher.encrypt(data)


def encrypt_cbc(data: bytes) -> bytes:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad
    import os

    key = os.urandom(16)
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(pad(data, AES.block_size))


def oracle(P: str, encrypt_fn) -> int:
    return len(encrypt_fn(compress(format_request(P).encode())))


def recover_sessionid(oracle) -> str:
    sessionid = ""
    charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+="
    repeat = 8

    while True:
        min_length = None
        min_count = None
        next_char = None

        for c in charset:
            test_sessionid = sessionid + c
            lengths = []
            # Stream: look for shortest compressed length.
            probe = ("sessionid=" + test_sessionid) * repeat
            length = oracle(probe)
            count = sum(1 for l in lengths if l == length)

            if min_length is None or length < min_length or (
                length == min_length and count > min_count
            ):
                min_length = length
                min_count = count
                next_char = c

        if next_char is None:
            break

        sessionid += next_char
        print(f"Recovered so far: {sessionid}")
        if next_char == "=":
            break

    return sessionid


def recover_sessionid_cbc(oracle, block_size: int = 16) -> str:
    sessionid = ""
    charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+="
    prefix_range = range(0, block_size)
    suffix_range = range(0, block_size)
    prefixes = [make_pad(n) for n in prefix_range]
    suffixes = [make_pad(n) for n in suffix_range]

    while True:
        candidate_len = len(sessionid) + 1
        baseline_lengths = []
        for prefix in prefixes:
            baseline_prefix = (
                prefix + "Cookie: sessionid=" + ("X" * candidate_len) + "\r\n"
            )
            row = []
            for suffix in suffixes:
                row.append(oracle(baseline_prefix + suffix))
            baseline_lengths.append(row)

        min_delta = None
        min_count = None
        next_char = None

        for c in charset:
            test_sessionid = sessionid + c
            delta = None
            count = 0
            for i, prefix in enumerate(prefixes):
                probe_prefix = prefix + "Cookie: sessionid=" + test_sessionid + "\r\n"
                base_row = baseline_lengths[i]
                for j, suffix in enumerate(suffixes):
                    # Sweep padding to cross CBC block boundaries.
                    d = oracle(probe_prefix + suffix) - base_row[j]
                    if delta is None or d < delta:
                        delta = d
                        count = 1
                    elif d == delta:
                        count += 1

            if min_delta is None or delta < min_delta or (
                delta == min_delta and count > min_count
            ):
                min_delta = delta
                min_count = count
                next_char = c

        if next_char is None or (min_delta is not None and min_delta >= 0):
            break

        sessionid += next_char
        print(f"Recovered so far: {sessionid}")
        if next_char == "=":
            break

    return sessionid


if __name__ == "__main__":
    recovered_stream = recover_sessionid(lambda P: oracle(P, encrypt_stream))
    print(f"Recovered sessionid (stream): {recovered_stream}")
    assert recovered_stream == SESSION_ID

    recovered_cbc = recover_sessionid_cbc(lambda P: oracle(P, encrypt_cbc), block_size=16)
    print(f"Recovered sessionid (cbc): {recovered_cbc}")
    assert recovered_cbc == SESSION_ID
