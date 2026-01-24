import hashlib
import secrets
from dataclasses import dataclass
from typing import Optional, Tuple

from Crypto.Cipher import AES

from easy import modexp, parse_hex_prime


def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len


def pkcs7_unpad(data: bytes) -> bytes:
    # For challange dont't worry about invalid padding
    pad_len = data[-1]
    return data[:-pad_len]


def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pkcs7_pad(plaintext, 16))


def aes_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return pkcs7_unpad(cipher.decrypt(ciphertext))


def sha1_key_from_shared_secret(s_int: int) -> bytes:
    s_bytes = s_int.to_bytes(s_int.bit_length() // 8 + 1, "big")
    return hashlib.sha1(s_bytes).digest()[:16]


P_HEX = """
ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024
e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd
3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec
6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f
24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361
c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552
bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff
fffffffffffff
""".strip()

P = parse_hex_prime(P_HEX)
G = 2


@dataclass
class DHParty:
    name: str
    p: int = P
    g: int = G
    secret: Optional[int] = None
    pub: Optional[int] = None
    peer_pub: Optional[int] = None
    aes_key: Optional[bytes] = None

    def generate(self, secret_bits: int) -> None:
        self.secret = secrets.randbits(secret_bits)
        self.pub = modexp(self.g, self.secret, self.p)

    def set_peer_pub(self, peer_pub: int) -> None:
        self.peer_pub = peer_pub
        s = modexp(peer_pub, self.secret, self.p)
        self.aes_key = sha1_key_from_shared_secret(s)

    def encrypt(self, msg: bytes) -> Tuple[bytes, bytes]:
        iv = secrets.token_bytes(16)
        ct = aes_cbc_encrypt(self.aes_key, iv, msg)
        return ct, iv

    def decrypt(self, ct: bytes, iv: bytes) -> bytes:
        return aes_cbc_decrypt(self.aes_key, iv, ct)


class EchoBot(DHParty):
    def on_message(self, ct: bytes, iv: bytes) -> Tuple[bytes, bytes]:
        # Decrypt, echo same plaintext back encrypted with a new random IV
        pt = self.decrypt(ct, iv)
        return self.encrypt(pt)


class MitM:
    def __init__(self, p: int):
        self.p = p
        self.injected_key = sha1_key_from_shared_secret(0)

    def decrypt_from_A(self, ct: bytes, iv: bytes) -> bytes:
        return aes_cbc_decrypt(self.injected_key, iv, ct)

    def decrypt_from_B(self, ct: bytes, iv: bytes) -> bytes:
        return aes_cbc_decrypt(self.injected_key, iv, ct)


def simulate_protocol_with_mitm():
    A = DHParty(name="A", p=P, g=G)
    B = EchoBot(name="B", p=P, g=G)
    M = MitM(p=P)

    # A and B generate secrets and public keys
    A.generate(secret_bits=679)
    B.generate(secret_bits=232)

    # B believes peer_pub is P MitM managed to fake A's key is P
    B.set_peer_pub(peer_pub=P)
    # A believes peer_pub is p MitM managed to fake B's key is P
    A.set_peer_pub(peer_pub=P)

    # A sends encrypted message to B (through M)
    message = b"hello echo bot, please echo this back"
    ct_A, iv_A = A.encrypt(message)

    # M receives A's ciphertext and decrypts it (because key is SHA1(0)[0:16])
    m_decrypted_from_A = M.decrypt_from_A(ct_A, iv_A)
    print("M decrypted A's message:", m_decrypted_from_A.decode("utf-8"))

    # M relays ciphertext to B unchanged
    ct_to_B, iv_to_B = ct_A, iv_A

    # B decrypts and echoes back a new ciphertext with a fresh IV
    ct_B, iv_B = B.on_message(ct_to_B, iv_to_B)

    # M intercepts B's echo and decrypts it
    m_decrypted_from_B = M.decrypt_from_B(ct_B, iv_B)
    print("M decrypted B's echo:", m_decrypted_from_B.decode("utf-8"))

    # M relays B's echo back to A unchanged
    ct_to_A, iv_to_A = ct_B, iv_B

    # A decrypts the echo
    a_recv = A.decrypt(ct_to_A, iv_to_A)
    print("A received echo:", a_recv.decode("utf-8"))

    expected = sha1_key_from_shared_secret(0)
    print("Key(A) =", A.aes_key.hex())
    print("Key(B) =", B.aes_key.hex())
    print("Key(expected SHA1(0)[0:16]) =", expected.hex())
    print("Keys equal?", A.aes_key == B.aes_key == expected)


def diffie_hellman_with_pk_set_to_p():
    # P^(anything) mod P = 0
    secret = secrets.randbits(200)
    s = modexp(P, secret, P)
    print(f"With pk set to P secret is: {s} (should be 0)")


if __name__ == "__main__":
    diffie_hellman_with_pk_set_to_p()
    simulate_protocol_with_mitm()
