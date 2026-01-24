import hashlib
import secrets


def modexp(base: int, exponent: int, modulus: int) -> int:
    if modulus == 1:
        return 0
    result = 1
    base = base % modulus
    e = exponent
    while e > 0:
        if e & 1:
            result = (result * base) % modulus
        # Calculate base for next '1' in exponent
        base = (base * base) % modulus
        e >>= 1
    return result


def derive_key_material(shared_secret_int: int) -> bytes:
    return hashlib.sha256(
        shared_secret_int.to_bytes(length=(shared_secret_int.bit_length() // 8 + 1))
    ).digest()


def parse_hex_prime(hex_lines: str) -> int:
    h = "".join(line.strip() for line in hex_lines.splitlines())
    return int.from_bytes(bytes.fromhex(h), "big")


def diffie_hellman():
    p_hex = """
ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024
e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd
3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec
6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f
24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361
c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552
bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff
fffffffffffff
""".strip()
    p = parse_hex_prime(p_hex)
    g = 2

    # Choose random secrets
    a = secrets.randbits(420)
    b = secrets.randbits(670)

    # Public keys
    A = modexp(g, a, p)
    print(f"A=\n{A}")
    B = modexp(g, b, p)
    print(f"B=\n{B}")

    # Shared secret
    s1 = modexp(B, a, p)
    print(f"s1=\n{s1}")
    s2 = modexp(A, b, p)
    print(f"s2=\n{s2}")
    print(f"Secrets match? {s1 == s2}")
    s = s1

    key_material = derive_key_material(s)

    enc_key = key_material[:16]
    mac_key = key_material[16:]

    print(f"SHA-256(s)={key_material.hex()}")
    print(f"enc_key={enc_key.hex()}")
    print(f"mac_key={mac_key.hex()}")


if __name__ == "__main__":
    diffie_hellman()
