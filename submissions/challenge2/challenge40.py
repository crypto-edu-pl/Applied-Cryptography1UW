"""
Cryptopals Challenge 40: E=3 RSA Broadcast Attack

Demonstrates Hastad's broadcast attack on RSA with e=3.

The vulnerability:
  If the same message m is encrypted with 3 different RSA public keys
  (all with e=3), an attacker can recover m without factoring.

The math:
  c0 = m^3 mod n0
  c1 = m^3 mod n1
  c2 = m^3 mod n2

  Using CRT: compute m^3 mod (n0 * n1 * n2)
  Since m < min(ni), we have m^3 < n0*n1*n2
  Therefore m^3 mod N = m^3 (no modular reduction)
  Take integer cube root to recover m.

For CRT to be meaningful, the message must be large enough that
m^3 > each individual ni (so modular reduction actually happens).

Mitigation: PKCS#1 padding randomizes each encryption.
"""

from utils import generate_rsa_keypair, rsa_encrypt, crt, integer_cube_root


def int_to_bytes(n: int) -> bytes:
    """Convert integer to bytes (big-endian)."""
    byte_len = (n.bit_length() + 7) // 8
    return n.to_bytes(byte_len, 'big') if byte_len > 0 else b'\x00'


def bytes_to_int(b: bytes) -> int:
    """Convert bytes to integer (big-endian)."""
    return int.from_bytes(b, 'big')


def broadcast_attack(ciphertexts: list, public_keys: list) -> int:
    """
    Perform e=3 broadcast attack using CRT.
    Given c_i = m^3 mod n_i, recovers m via CRT + cube root.
    """
    moduli = [pk[1] for pk in public_keys]
    m_cubed = crt(ciphertexts, moduli)
    return integer_cube_root(m_cubed)


def main():
    print("=== Challenge 40: E=3 RSA Broadcast Attack ===\n")

    # Setup: 3 RSA keypairs with e=3
    print("1. Generate 3 RSA keypairs with e=3")
    keys = [generate_rsa_keypair(bits=512, e=3) for _ in range(3)]
    public_keys = [pub for pub, _ in keys]
    moduli = [n for (e, n) in public_keys]
    for i, (e, n) in enumerate(public_keys):
        print(f"   n{i} = {hex(n)[:40]}... ({n.bit_length()} bits)")

    # Encrypt same message under all 3 keys
    print("\n2. Encrypt same plaintext under all 3 public keys")
    secret = b"TOP SECRET: The nuclear launch codes are ALPHA-7749-WHISKEY-TANGO"
    m = bytes_to_int(secret)
    print(f"   Plaintext: '{secret.decode()}'")
    print(f"   m = {str(m)[:50]}... ({m.bit_length()} bits)")

    m_cubed = m ** 3
    min_n = min(moduli)
    print(f"   m^3 = {m_cubed.bit_length()} bits, each n ~ {min_n.bit_length()} bits")
    print(f"   m^3 > n: {m_cubed > min_n} (modular reduction will occur)")

    ciphertexts = [rsa_encrypt(m, pub) for pub in public_keys]
    print(f"\n   Ciphertexts c_i = m^3 mod n_i:")
    for i, c in enumerate(ciphertexts):
        print(f"   c{i} = {str(c)[:50]}...")

    # Perform attack
    print("\n3. Attack: Apply Chinese Remainder Theorem, then cube root")
    N = moduli[0] * moduli[1] * moduli[2]
    m_cubed_recovered = crt(ciphertexts, moduli)
    print(f"   CRT combines residues to get m^3 mod N")
    print(f"   N = n0 * n1 * n2 = {N.bit_length()} bits")
    print(f"   m^3 < N: {m_cubed_recovered < N} (no information lost)")

    recovered_m = integer_cube_root(m_cubed_recovered)
    recovered = int_to_bytes(recovered_m)
    print(f"\n   Taking cube root of m^3...")
    print(f"   Recovered: '{recovered.decode()}'")

    assert recovered == secret
    print(f"   Attack successful")


if __name__ == "__main__":
    main()
