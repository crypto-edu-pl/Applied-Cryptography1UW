from Crypto.Util.number import getPrime
from collections import namedtuple
from binascii import hexlify, unhexlify
from sys import argv

PublicKey = namedtuple("PublicKey", "n e")
SecretKey = namedtuple("SecretKey", "n d")


def invmod(x, n):
    s0, r0 = 0, n
    s1, r1 = 1, x

    while r1 > 0:
        q, r = divmod(r0, r1)
        s0, s1 = s1, s0 - q * s1
        r0, r1 = r1, r

    if r0 == 1:
        return s0 % n
    else:
        return None


def rsa_genkeys(bits, e=65537):
    # To have a key of a given length we need two primes half that length
    bits //= 2

    while True:
        p, q = getPrime(bits), getPrime(bits)
        while p == q:
            q = getPrime(bits)

        phi = (p - 1) * (q - 1)
        d = invmod(e, phi)
        if d != None:
            break

    n = p * q
    return (PublicKey(n, e), SecretKey(n, d))


def rsa_encrypt(m, pk):
    m = int(hexlify(m.encode()), 16)
    return pow(m, pk.e, pk.n)


def rsa_decrypt(m, sk):
    m = pow(m, sk.d, sk.n)
    return unhexlify(hex(m)[2:]).decode()


if __name__ == "__main__":
    if len(argv) < 2:
        print("USAGE: python3 medium.py keys/encrypt/decrypt/demo [OPTIONS]")
        exit(1)

    if argv[1] == "keys":
        bits = 2048
        if len(argv) >= 3:
            bits = int(argv[2])

        print("\x1b[1mGenerating your new key pair...\x1b[0m")
        pk, sk = rsa_genkeys(bits)
        print("\x1b[1mYour secret key:\x1b[0m")
        print("\x1b[1md = \x1b[0;91m{}\x1b[0m".format(sk.d))
        print("\x1b[1mYour public key:\x1b[0m")
        print("\x1b[1me = \x1b[0;92m{}\x1b[0m".format(pk.e))
        print("\x1b[1mN = \x1b[0;92m{}\x1b[0m".format(pk.n))

    elif argv[1] == "encrypt":
        if len(argv) != 5:
            print("USAGE: python3 medium.py encrypt [MESSAGE] [E] [N]")
            exit(1)

        pt = argv[2]
        pk = PublicKey(e=int(argv[3]), n=int(argv[4]))
        ct = rsa_encrypt(pt, pk)
        print("\x1b[1mCiphertext: \x1b[0;93m{}\x1b[0m".format(ct))

    elif argv[1] == "decrypt":
        if len(argv) != 5:
            print("USAGE: python3 medium.py decrypt [MESSAGE] [D] [N]")
            exit(1)

        ct = int(argv[2])
        sk = SecretKey(d=int(argv[3]), n=int(argv[4]))
        pt = rsa_decrypt(ct, sk)
        print("\x1b[1mPlaintext: \x1b[0;92m{}\x1b[0m".format(pt))

    elif argv[1] == "demo":
        bits = 2048
        if len(argv) >= 3:
            bits = int(argv[2])

        pt = "Hello world!"

        print("\x1b[1mGenerating a new key pair...\x1b[0m")
        pk, sk = rsa_genkeys(bits)
        print("\x1b[1mN = \x1b[0;92m{}\x1b[0m".format(pk.n))
        print("\x1b[1me = \x1b[0;92m{}\x1b[0m".format(pk.e))
        print("\x1b[1md = \x1b[0;91m{}\x1b[0m".format(sk.d))
        print()
        print('\x1b[1mOriginal message \x1b[0;93m"{}"\x1b[0m'.format(pt))
        ct = rsa_encrypt(pt, pk)
        print("\x1b[1mCiphertext: \x1b[0;92m{}\x1b[0m".format(ct))
        pt = rsa_decrypt(ct, sk)
        print('\x1b[1mDecrypted message \x1b[0;93m"{}"\x1b[0m'.format(pt))

    else:
        print("USAGE: python3 medium.py keys/encrypt/decrypt/demo [OPTIONS]")
        exit(1)
