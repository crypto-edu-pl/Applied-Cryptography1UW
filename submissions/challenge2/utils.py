import math
import os
from typing import Tuple

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import getPrime
from sympy import integer_nthroot
from sympy.ntheory.modular import crt as sympy_crt


# AES-CBC Encryption/Decryption

def aes_cbc_encrypt(plaintext: bytes, key: bytes, iv: bytes = None) -> Tuple[bytes, bytes]:
    """
    Encrypt plaintext using AES-CBC mode.
    Returns (ciphertext, iv).
    """
    if iv is None:
        iv = os.urandom(16)

    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    return ciphertext, iv


def aes_cbc_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """Decrypt ciphertext using AES-CBC mode."""
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size)

# Number Theory Utilities

def invmod(a: int, n: int) -> int:
    """Compute modular multiplicative inverse of a mod n."""
    return pow(a, -1, n)


def integer_cube_root(n: int) -> int:
    """Return the largest integer x such that x^3 <= n."""
    root, _ = integer_nthroot(n, 3)
    return root


def crt(residues: list, moduli: list) -> int:
    """Chinese Remainder Theorem. Find x such that x = ri (mod mi) for all i."""
    result, _ = sympy_crt(moduli, residues)
    return int(result)

# RSA Utilities

def generate_rsa_keypair(bits: int = 512, e: int = 3) -> Tuple[Tuple[int, int], Tuple[int, int]]:
    """Generate RSA keypair. Returns ((e, n), (d, n))."""
    while True:
        p = getPrime(bits)
        q = getPrime(bits)

        if p == q:
            continue

        n = p * q
        phi = (p - 1) * (q - 1)

        if math.gcd(e, phi) != 1:
            continue

        d = invmod(e, phi)
        return ((e, n), (d, n))


def rsa_encrypt(m: int, public_key: Tuple[int, int]) -> int:
    """Encrypt message m using RSA public key."""
    e, n = public_key
    return pow(m, e, n)


# Diffie-Hellman Parameters

# NIST 1024-bit MODP group (RFC 2409)
NIST_P = int(
    "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024"
    "e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd"
    "3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec"
    "6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f"
    "24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361"
    "c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552"
    "bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff"
    "fffffffffffff", 16
)
NIST_G = 2