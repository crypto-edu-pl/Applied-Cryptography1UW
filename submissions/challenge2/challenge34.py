"""
Cryptopals Challenge 34: Implement a MITM Key-Fixing Attack on DH

Demonstrates the key-fixing attack where a Man-in-the-Middle attacker
replaces both parties' public keys with 'p', causing both to compute
a shared secret of 0.

The attack:
  1. Alice sends (p, g, A) to Bob
  2. Attacker intercepts, sends (p, g, p) to Bob instead
  3. Bob sends B to Alice
  4. Attacker intercepts, sends p to Alice instead
  5. Both parties compute: s = p^x mod p = 0
  6. Attacker knows s = 0, derives same key, decrypts everything

Why p^x mod p = 0:
  p mod p = 0, so p^x mod p = 0 for any x
"""

import hashlib
import secrets
from utils import NIST_P, NIST_G, aes_cbc_encrypt, aes_cbc_decrypt


def derive_key(shared_secret: int) -> bytes:
    """Derive AES key from shared secret using SHA256."""
    secret_bytes = shared_secret.to_bytes(
        (shared_secret.bit_length() + 7) // 8, 'big'
    ) if shared_secret > 0 else b'\x00'
    return hashlib.sha256(secret_bytes).digest()[:16]


class Party:
    """A participant in DH key exchange."""

    def __init__(self, name: str):
        self.name = name
        self.p = self.g = None
        self.private_key = self.public_key = None
        self.key = None

    def init_params(self, p: int, g: int):
        """Initialize with DH parameters and generate keypair."""
        self.p, self.g = p, g
        self.private_key = secrets.randbelow(p - 1) + 1
        self.public_key = pow(g, self.private_key, p)

    def compute_secret(self, their_public: int):
        """Compute shared secret and derive AES key."""
        shared = pow(their_public, self.private_key, self.p)
        self.key = derive_key(shared)
        return shared

    def encrypt(self, message: bytes) -> tuple:
        """Encrypt message with AES-CBC."""
        return aes_cbc_encrypt(message, self.key)

    def decrypt(self, ciphertext: bytes, iv: bytes) -> bytes:
        """Decrypt message with AES-CBC."""
        return aes_cbc_decrypt(ciphertext, self.key, iv)


class Attacker:
    """MITM attacker performing key-fixing attack."""

    def __init__(self):
        self.p = None
        self.key = derive_key(0)  # s=0 is known

    def intercept_params(self, p: int, g: int, pub: int) -> tuple:
        """Intercept (p,g,A), return (p,g,p)."""
        self.p = p
        return (p, g, p)

    def intercept_pubkey(self, pub: int) -> int:
        """Intercept B, return p instead."""
        return self.p

    def decrypt(self, ciphertext: bytes, iv: bytes) -> bytes:
        """Decrypt intercepted message."""
        return aes_cbc_decrypt(ciphertext, self.key, iv)


def main():
    print("=== Challenge 34: MITM Key-Fixing Attack ===\n")

    alice = Party("Alice")
    bob = Party("Bob")
    mallory = Attacker()

    # Normal protocol
    print("1. Normal DH exchange (no attacker)")
    alice.init_params(NIST_P, NIST_G)
    bob.init_params(NIST_P, NIST_G)
    s1 = alice.compute_secret(bob.public_key)
    s2 = bob.compute_secret(alice.public_key)
    print(f"   Alice computes: s = B^a mod p = {hex(s1)[:32]}...")
    print(f"   Bob computes:   s = A^b mod p = {hex(s2)[:32]}...")
    print(f"   Secrets match: {s1 == s2} (both non-zero)\n")

    # MITM attack
    print("2. MITM attack (Mallory intercepts and replaces public keys)")
    alice.init_params(NIST_P, NIST_G)
    print(f"   Alice -> Mallory: A = {hex(alice.public_key)[:32]}...")
    print(f"   Mallory -> Bob:   A' = p (replaced)")

    p, g, fake_A = mallory.intercept_params(NIST_P, NIST_G, alice.public_key)
    bob.init_params(p, g)
    s_bob = bob.compute_secret(fake_A)  # p^b mod p = 0
    print(f"   Bob computes: s = A'^b mod p = p^b mod p = {s_bob}")

    print(f"   Bob -> Mallory: B = {hex(bob.public_key)[:32]}...")
    print(f"   Mallory -> Alice: B' = p (replaced)")

    fake_B = mallory.intercept_pubkey(bob.public_key)
    s_alice = alice.compute_secret(fake_B)  # p^a mod p = 0
    print(f"   Alice computes: s = B'^a mod p = p^a mod p = {s_alice}\n")

    # Verify attack success
    print("3. Result: All three parties derived the same key")
    print(f"   Alice's key:   {alice.key.hex()}")
    print(f"   Bob's key:     {bob.key.hex()}")
    print(f"   Mallory's key: {mallory.key.hex()}")
    print(f"   Keys match: {alice.key == bob.key == mallory.key}\n")

    # Mallory intercepts messages
    print("4. Mallory decrypts intercepted traffic")
    secret = b"SECRET: The launch code is 12345"
    ct, iv = alice.encrypt(secret)
    print(f"   Alice sends:      '{secret.decode()}'")
    print(f"   Mallory decrypts: '{mallory.decrypt(ct, iv).decode()}'")
    print(f"   Bob receives:     '{bob.decrypt(ct, iv).decode()}'")


if __name__ == "__main__":
    main()
