"""
Cryptopals Challenge 33: Implement Diffie-Hellman

Implements the Diffie-Hellman key exchange protocol:
1. Small parameter demo (p=37, g=5)
2. NIST 1024-bit parameters

The math:
  - Public parameters: prime p, generator g
  - Alice: private a, public A = g^a mod p
  - Bob: private b, public B = g^b mod p
  - Shared secret: s = B^a mod p = A^b mod p = g^(ab) mod p
"""

import secrets
from utils import NIST_P, NIST_G


def diffie_hellman_keypair(p: int, g: int) -> tuple:
    """
    Generate a Diffie-Hellman key pair.
    Returns (private_key, public_key) where public = g^private mod p.
    """
    private_key = secrets.randbelow(p - 1) + 1
    public_key = pow(g, private_key, p)
    return private_key, public_key


def compute_shared_secret(their_public: int, my_private: int, p: int) -> int:
    """
    Compute shared secret: their_public^my_private mod p.
    Both parties compute the same value: g^(ab) mod p.
    """
    return pow(their_public, my_private, p)


def main():
    print("=== Challenge 33: Diffie-Hellman Key Exchange ===\n")

    # Part 1: Small parameters
    print("1. Small parameters (p=37, g=5)")
    p, g = 37, 5
    a, A = diffie_hellman_keypair(p, g)
    b, B = diffie_hellman_keypair(p, g)
    print(f"   Alice: private a={a}, public A=g^a mod p = {A}")
    print(f"   Bob:   private b={b}, public B=g^b mod p = {B}")

    s_alice = compute_shared_secret(B, a, p)
    s_bob = compute_shared_secret(A, b, p)
    print(f"   Alice computes: B^a mod p = {s_alice}")
    print(f"   Bob computes:   A^b mod p = {s_bob}")
    assert s_alice == s_bob
    print(f"   Shared secrets match!\n")

    # Part 2: NIST 1024-bit parameters
    print("2. NIST 1024-bit parameters (g=2)")
    a, A = diffie_hellman_keypair(NIST_P, NIST_G)
    b, B = diffie_hellman_keypair(NIST_P, NIST_G)
    print(f"   Alice public A: {hex(A)[:40]}... ({A.bit_length()} bits)")
    print(f"   Bob public B:   {hex(B)[:40]}... ({B.bit_length()} bits)")

    s_alice = compute_shared_secret(B, a, NIST_P)
    s_bob = compute_shared_secret(A, b, NIST_P)
    assert s_alice == s_bob
    print(f"   Shared secret:  {hex(s_alice)[:40]}... ({s_alice.bit_length()} bits)")
    print(f"   Secrets match")


if __name__ == "__main__":
    main()
