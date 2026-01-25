# 34. MITM key-fixing attack on Diffie-Hellman

import os
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


P = int(
    "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024"
    "e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd"
    "3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec"
    "6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f"
    "24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361"
    "c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552"
    "bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff"
    "fffffffffffff",
    16,
)
G = 2


def dh_generate_keypair():
    """Generate DH private and public keys."""
    private_key = int.from_bytes(os.urandom(32), 'big') % P
    public_key = pow(G, private_key, P)
    return private_key, public_key


def dh_compute_secret(private_key, other_public_key):
    """Compute shared secret."""
    return pow(other_public_key, private_key, P)


def derive_aes_key(shared_secret):
    """Derive AES key from shared secret using SHA1."""
    secret_bytes = shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, 'big')
    sha1_hash = hashlib.sha1(secret_bytes).digest()
    return sha1_hash[:16]


def encrypt_message(key, plaintext):
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = pad(plaintext.encode(), 16)
    ciphertext = cipher.encrypt(padded)
    return ciphertext + iv


def decrypt_message(key, data):
    ciphertext = data[:-16]
    iv = data[-16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = cipher.decrypt(ciphertext)
    return unpad(padded, 16).decode()


class Party:
    """Represents a party in the DH exchange."""

    def __init__(self, name):
        self.private_key, self.public_key = dh_generate_keypair()
        self.shared_secret = None
        self.aes_key = None

    def receive_public_key(self, other_public_key):
        self.shared_secret = dh_compute_secret(self.private_key, other_public_key)
        self.aes_key = derive_aes_key(self.shared_secret)

    def send_message(self, message):
        return encrypt_message(self.aes_key, message)

    def receive_message(self, encrypted_data):
        return decrypt_message(self.aes_key, encrypted_data)


def normal_protocol():
    print("=" * 60)
    print("NORMAL PROTOCOL")
    print("=" * 60)

    # Create parties
    alice = Party("Alice")
    bob = Party("Bob")

    # A->B: Send "p", "g", "A"
    print(f"\nAlice -> Bob: p, g, A={alice.public_key}")

    # B->A: Send "B"
    print(f"Bob -> Alice: B={bob.public_key}")

    # Both compute shared secret
    alice.receive_public_key(bob.public_key)
    bob.receive_public_key(alice.public_key)

    print(f"\nAlice's shared secret: {alice.shared_secret}")
    print(f"Bob's shared secret: {bob.shared_secret}")
    print(f"Secrets match: {alice.shared_secret == bob.shared_secret}")
    assert alice.shared_secret == bob.shared_secret

    # A->B: Send encrypted message
    message = "Secret message from A to B"
    encrypted = alice.send_message(message)
    print(f"\nAlice -> Bob: {encrypted.hex()[:64]}... (encrypted)")

    # B receives and decrypts
    decrypted = bob.receive_message(encrypted)
    print(f"Bob decrypted: '{decrypted}'")

    # B->A: Echo back
    echo_encrypted = bob.send_message(decrypted)
    print(f"\nBob -> Alice: {echo_encrypted.hex()[:64]}... (encrypted echo)")

    # A receives echo
    echo_decrypted = alice.receive_message(echo_encrypted)
    print(f"Alice received echo: '{echo_decrypted}'")


class MITM:
    """Man-in-the-Middle attacker."""

    def __init__(self):
        # In the parameter injection attack, both sides will compute s = p^x mod p = 0
        # So we know the shared secret will be 0
        self.injected_secret = 0
        self.aes_key = derive_aes_key(self.injected_secret)

    def intercept_and_decrypt(self, encrypted_data, direction):
        """Intercept and decrypt a message."""
        decrypted = decrypt_message(self.aes_key, encrypted_data)
        print(f"\n[MITM DECRYPTED {direction}]: '{decrypted}'")
        return encrypted_data  # Relay the original encrypted data


def mitm_attack():
    print("\n" + "=" * 60)
    print("MITM")
    print("=" * 60)

    alice = Party("Alice")
    bob = Party("Bob")
    mallory = MITM()

    # A->M: Send "p", "g", "A"
    print(f"\nAlice -> MITM: p, g, A={alice.public_key}")

    # M->B: Send "p", "g", "p"
    print(f"MITM -> Bob: p, g, p (INJECTED p={P})")

    # B->M: Send "B"
    print(f"Bob -> Mallory: B={bob.public_key}")

    # M->A: Send "p"
    print(f"MITM -> Alice: p (INJECTED p={P})")

    # Both compute shared secret (which will be 0)
    alice.receive_public_key(P)
    bob.receive_public_key(P)

    print(f"\nAlice's shared secret: {alice.shared_secret}")
    print(f"Bob's shared secret: {bob.shared_secret}")
    print(f"MITM knows the secret: {mallory.injected_secret}")
    print(f"\nAll parties have the same secret (0): {alice.shared_secret == bob.shared_secret == mallory.injected_secret}")
    assert alice.shared_secret == bob.shared_secret == mallory.injected_secret

    # A->M: Send encrypted message
    message = "Secret message from A to B"
    encrypted = alice.send_message(message)
    print(f"\nAlice -> MITM: {encrypted.hex()[:64]}... (encrypted)")

    # M intercepts and decrypts
    relayed = mallory.intercept_and_decrypt(encrypted, "A->B")

    # M->B: Relay to Bob
    print(f"MITM -> Bob: (relaying encrypted message)")
    # B receives and decrypts
    decrypted = bob.receive_message(relayed)
    print(f"Bob decrypted: '{decrypted}'")

    # B->M: Echo back
    echo_encrypted = bob.send_message(decrypted)
    print(f"\nBob -> Mallory: {echo_encrypted.hex()[:64]}... (encrypted echo)")

    # M intercepts and decrypts the echo
    relayed_echo = mallory.intercept_and_decrypt(echo_encrypted, "B->A")

    # M->A: Relay to Alice
    print(f"Mallory -> Alice: (relaying encrypted echo)")

    # A receives echo
    echo_decrypted = alice.receive_message(relayed_echo)
    print(f"Alice received echo: '{echo_decrypted}'")


if __name__ == "__main__":
    normal_protocol()
    mitm_attack()
