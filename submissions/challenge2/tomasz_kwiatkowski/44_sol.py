import hashlib
import sys


p = int(
    "800000000000000089e1855218a0e7dac38136ffafa72eda7"
    "859f2171e25e65eac698c1702578b07dc2a1076da241c76c6"
    "2d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebe"
    "ac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2"
    "b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc87"
    "1a584471bb1",
    16,
)
q = int("f4f47f05794b256174bba6e9b396a7707e563c5b", 16)
g = int(
    "5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119"
    "458fef538b8fa4046c8db53039db620c094c9fa077ef389b5"
    "322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a047"
    "0f5b64c36b625a097f1651fe775323556fe00b3608c887892"
    "878480e99041be601a62166ca6894bdd41a7054ec89f756ba"
    "9fc95302291",
    16,
)


def read_messages():
    data = sys.stdin.read().strip()
    lines = data.split("\n")

    n = len(lines)
    if n % 4 != 0:
        raise ValueError("Invalid input format.")

    print("Read", len(lines) // 4, "messages.")

    messages_signed: list[tuple[str, int, int, int]] = []
    for i in range(0, len(lines), 4):
        message = lines[i].removeprefix("msg: ")
        s = int(lines[i + 1].removeprefix("s: "))
        r = int(lines[i + 2].removeprefix("r: "))
        m = int(lines[i + 3].removeprefix("m: "), 16)
        messages_signed.append((message, r, s, m))

    return messages_signed


def try_recover_nonce(
    msg1: tuple[str, int, int, int],
    msg2: tuple[str, int, int, int],
) -> int | None:
    """
    Given two messages (m1, m2) signed with the same nonce k,
    we can recover k as follows:

    s1 = (k^-1 * (m1 + x * r)) mod q  (1)
    s2 = (k^-1 * (m2 + x * r)) mod q  (2)

    s1 * k = m1 + x * r  (1)
    s2 * k = m2 + x * r  (2)

    From (1) - (2):
    s1 * k - s2 * k = m1 - m2
    k = (m1 - m2) * (s1 - s2)^-1 mod q
    """

    _, r1, s1, m1 = msg1
    _, r2, s2, m2 = msg2

    if r1 != r2:
        return None
    try:
        s_diff_inv = pow(s1 - s2, -1, q)
    except ValueError:
        return None

    k = (m1 - m2) * s_diff_inv % q
    return k


def main():
    messages_signed = read_messages()

    for i in range(len(messages_signed)):
        for j in range(i + 1, len(messages_signed)):
            k = try_recover_nonce(messages_signed[i], messages_signed[j])
            if k is not None:
                print(f"Recovered nonce k: 0x{k:x}")

                _, r, s, m = messages_signed[i]
                # Recover private key from known k.
                x = (k * s - m) * pow(r, -1, q) % q
                print(f"Private key x: 0x{x:x}")

                x_hex = f"{x:x}"
                sha1_x_hex = hashlib.sha1(x_hex.encode()).hexdigest()
                print(f"SHA-1(hex(x)): {sha1_x_hex}")

                assert sha1_x_hex == "ca8f6f7c66fa362d40760d135b763eb8527d3d52"

                return

    print("No repeated nonce found.")


if __name__ == "__main__":
    main()
