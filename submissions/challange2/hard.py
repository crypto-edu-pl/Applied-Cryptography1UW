import math
import secrets


def egcd(a: int, b: int) -> tuple[int, int, int]:
    """
    Extended Euclidean Algorithm.
    """
    if b == 0:
        return (a, 1, 0)
    g, x1, y1 = egcd(b, a % b)
    return (g, y1, x1 - (a // b) * y1)


def invmod(a: int, m: int) -> int:
    """
    Modular inverse of a mod m, assuming gcd(a, m) == 1.
    """
    _, x, _ = egcd(a, m)
    return x % m


def crt_combine(residues: list[int], moduli: list[int]) -> int:
    """
    Combine residues using the Chinese Remainder Theorem and return the
    canonical representative in [0, N-1], where N is the product of moduli.
    """
    k = len(moduli)
    N = 1
    for n in moduli:
        N *= n

    result = 0
    for i in range(k):
        n_i = moduli[i]
        c_i = residues[i]
        m_s_i = N // n_i
        inv_i = invmod(m_s_i, n_i)
        term = c_i * m_s_i * inv_i
        result += term

    return result % N


def integer_cube_root(n: int) -> int:
    # Only positive
    return math.ceil(n ** (1 / 3))


def gen_prime(bits: int) -> int:
    """
    Generate prime with specified bits length.
    """
    while True:
        candidate = (
            secrets.randbits(bits) | (1 << (bits - 1)) | 1
        )  # Ensure bit length and odd
        is_prime = True
        for i in range(3, math.ceil(math.sqrt(candidate))):
            if candidate % i == 0:
                is_prime = False
                break
        if is_prime:
            return candidate


def rsa_keygen(bits: int, e: int = 3) -> tuple[int, int, int]:
    """
    Generate an RSA keypair (n, e, d) with public exponent e=3
    """
    while True:
        p = gen_prime(bits // 2)
        q = gen_prime(bits // 2)
        # Different primes
        if p == q:
            continue
        n = p * q
        phi = (p - 1) * (q - 1)
        # e and phi need to be coprime and e=3 is prime, so check if 3| phi
        if phi % e == 0:
            continue
        d = invmod(e, phi)
        return (n, e, d)


def rsa_encrypt_no_padding(m: int, n: int, e: int = 3) -> int:
    return pow(m, e, n)


def rsa_decrypt_no_padding(c: int, n: int, d: int) -> int:
    return pow(c, d, n)


def broadcast_attack_e3(ciphertexts: list[int], moduli: list[int]) -> int:
    combined = crt_combine(ciphertexts, moduli)
    m = integer_cube_root(combined)
    return m


def rsa_broadcast():
    # Public exponent e=3
    e = 3

    # Generate three RSA keypairs to show the attack.
    keypairs = [rsa_keygen(bits=64, e=e) for _ in range(3)]
    list_of_n = [kp[0] for kp in keypairs]

    # Ensure pairwise coprime
    assert math.gcd(list_of_n[0], list_of_n[1]) == 1
    assert math.gcd(list_of_n[0], list_of_n[2]) == 1
    assert math.gcd(list_of_n[1], list_of_n[2]) == 1

    # Random message m^3 < 64
    m = secrets.randbits(16)

    # Encrypt the same message under each modulus, no padding
    ciphertexts = [rsa_encrypt_no_padding(m, list_of_n[i], e) for i in range(3)]

    recovered = broadcast_attack_e3(ciphertexts, list_of_n)

    print(f"Original m:   {m}")
    print(f"Recovered m:  {recovered}")
    print(f"Match:        {m == recovered}")


if __name__ == "__main__":
    rsa_broadcast()
