import hashlib
import secrets


class DiffieHellman:
    p = int(
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
    g = 2
    secret: int | None = None

    def __init__(self, p: int | None = None, g: int | None = None) -> None:
        self.p = p or self.p
        self.g = g or self.g

        self._priv = secrets.randbelow(self.p)
        self.pub = pow(self.g, self._priv, self.p)

    def set_key(self, other_pub: int):
        s = pow(other_pub, self._priv, self.p)
        # Hash the shared secret to derive a fixed-size key.
        self.secret = int(
            hashlib.sha256(s.to_bytes((s.bit_length() + 7) // 8, "big")).hexdigest(),
            16,
        )

    def get_key(self) -> int:
        if self.secret is None:
            raise ValueError("Secret key not established yet.")
        return self.secret


A = DiffieHellman()
B = DiffieHellman()

print("Public keys:")
print(f"A = 0x{A.pub:0x}")
print(f"B = 0x{B.pub:0x}")

A.set_key(B.pub)
B.set_key(A.pub)

print("\nShared secret keys (should be the same):")
print(f"0x{A.get_key():0x}")
print(f"0x{B.get_key():0x}")
assert A.get_key() == B.get_key()
