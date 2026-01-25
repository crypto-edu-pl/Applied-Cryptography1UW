# 41. Unpadded message recovery oracle

import json
import hashlib
import time
import random
from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes


def generate_rsa_keypair(bits=1024):
    """
    Generate an RSA key pair.
    Returns (public_key, private_key), where each key is a tuple (exponent, modulus).
    """
    e = 65537

    # Generate two distinct primes
    p = getPrime(bits // 2)
    q = getPrime(bits // 2)
    while p == q:
        q = getPrime(bits // 2)

    n = p * q
    phi = (p - 1) * (q - 1)

    # Ensure e and phi are coprime
    while True:
        try:
            d = inverse(e, phi)
            break
        except:
            p = getPrime(bits // 2)
            q = getPrime(bits // 2)
            n = p * q
            phi = (p - 1) * (q - 1)

    return (e, n), (d, n)


def rsa_encrypt(plaintext, public_key):
    """Encrypt a message with RSA (no padding)."""
    e, n = public_key
    m = bytes_to_long(plaintext)
    c = pow(m, e, n)
    return c


def rsa_decrypt(ciphertext, private_key):
    """Decrypt a ciphertext with RSA."""
    d, n = private_key
    m = pow(ciphertext, d, n)
    return long_to_bytes(m)


class VulnerableServer:
    """
    A server that decrypts RSA messages but prevents replay attacks
    by tracking ciphertext hashes.
    """

    def __init__(self, private_key):
        self.private_key = private_key
        self.seen_hashes = set()

    def decrypt_message(self, ciphertext):
        """
        Decrypt a ciphertext, but reject if we've seen it before.
        Returns the plaintext or None if rejected.
        """
        # Hash the ciphertext
        ct_hash = hashlib.sha256(str(ciphertext).encode()).hexdigest()

        # Check if we've seen this before
        if ct_hash in self.seen_hashes:
            print(f"[Server] Rejecting duplicate ciphertext (hash: {ct_hash[:16]}...)")
            return None

        # Record this hash
        self.seen_hashes.add(ct_hash)

        # Decrypt and return
        plaintext = rsa_decrypt(ciphertext, self.private_key)
        print(f"[Server] Decrypted message: {plaintext}")
        return plaintext


def create_message():
    """Create a timestamped message."""
    message = {
        "time": int(time.time()),
        "social": "555-55-5555"
    }
    return json.dumps(message).encode()


def attack():
    # Generate RSA keys
    public_key, private_key = generate_rsa_keypair(1024)
    e, n = public_key
    print(f"Generated RSA public key: (e={e}, n={n})")

    # Create server
    server = VulnerableServer(private_key)

    # Step 1: Intercept a legitimate encrypted message
    print("\n" + "=" * 60)
    print("STEP 1: Intercept encrypted message from victim")
    print("=" * 60)

    victim_message = create_message()
    print(f"\nVictim's plaintext message: {victim_message}")

    C = rsa_encrypt(victim_message, public_key)
    print(f"Intercepted ciphertext C: {C}")

    # Step 2: Try to decrypt directly (this will work once)
    print("\n" + "=" * 60)
    print("STEP 2: Decrypt the intercepted message once")
    print("=" * 60)

    decrypted = server.decrypt_message(C)
    print(f"Decrypted message from server: {decrypted}")

    # Step 3: Try to decrypt the same message again (will be rejected)
    print("\n" + "=" * 60)
    print("STEP 3: Try to decrypt the same message again")
    print("=" * 60)

    decrypted = server.decrypt_message(C)
    if decrypted is None:
        print("Server rejected the duplicate message")

    # Step 4: Perform the attack
    print("\n" + "=" * 60)
    print("STEP 4: Generate C'")
    print("=" * 60)

    # Choose a random S > 1 mod N
    S = random.randint(2, n - 1)

    # Compute C' = (S^E * C) mod N
    S_to_E = pow(S, e, n)
    C_prime = (S_to_E * C) % n

    print(f"Ciphertext C': {C_prime}")
    print(f"\nC' is different from C: {C_prime != C}")

    # Step 5: Submit C' to the server
    print("\n" + "=" * 60)
    print("STEP 5: Submit C' to server")
    print("=" * 60)

    P_prime = server.decrypt_message(C_prime)

    if P_prime is None:
        print("Attack failed - server rejected the message")
        return

    print(f"Server returned P': {P_prime}")

    # Step 6: Recover the original plaintext
    print("\n" + "=" * 60)
    print("STEP 6: Recover original plaintext P from P'")
    print("=" * 60)

    # P = P' / S mod N
    # Convert P' back to integer
    P_prime_int = bytes_to_long(P_prime)

    # Compute S^(-1) mod N
    S_inv = inverse(S, n)
    print(f"\nS^(-1) mod N: {S_inv}")

    # Recover P
    P_recovered = (P_prime_int * S_inv) % n
    recovered_plaintext = long_to_bytes(P_recovered)

    print(f"\nRecovered plaintext: {recovered_plaintext}")
    print(f"Original plaintext:  {victim_message}")
    print(f"\nAttack successful: {recovered_plaintext == victim_message}")


if __name__ == "__main__":
    attack()
