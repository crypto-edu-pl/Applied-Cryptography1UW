from medium import invmod, rsa_genkeys, rsa_encrypt
from math import cbrt
from binascii import unhexlify
from sys import argv


def chinese_remainder_theorem(values):
    modulus = 1
    for _, n in values:
        modulus *= n

    result = 0
    for r, n in values:
        a = modulus // n
        result += (a * invmod(a, n) * r) % modulus
        result %= modulus

    return result


def icbrt(n):
    x = n // 2

    while x != n // (x * x):
        x = (x + (n // (x * x))) // 2

    return x


def rsa_broadcast_attack(msg1, msg2, msg3):
    cube = chinese_remainder_theorem([(ct, pk.n) for (ct, pk) in [msg1, msg2, msg3]])
    print(
        "\x1b[1mReconstructed the original value without modulus: \x1b[0;92m{}\x1b[0m".format(
            cube
        )
    )
    ptx = icbrt(cube)
    print("\x1b[1mCube root of the value is: \x1b[0;92m{}\x1b[0m".format(ptx))
    ptx = unhexlify(hex(ptx)[2:]).decode()
    return ptx


if __name__ == "__main__":
    bits = 2048
    if len(argv) >= 2:
        bits = int(argv[1])

    msg = 'Dear Tutors, password to the grading system is "hunter2" -- Prof'

    print("\x1b[1mGenerating the key of the first recipient\x1b[0m")
    (pk1, _) = rsa_genkeys(bits, 3)
    print("\x1b[1mGenerating the key of the second recipient\x1b[0m")
    (pk2, _) = rsa_genkeys(bits, 3)
    print("\x1b[1mGenerating the key of the third recipient\x1b[0m")
    (pk3, _) = rsa_genkeys(bits, 3)

    print("\x1b[1mThe sender sends a message.\x1b[0m")
    ct1 = rsa_encrypt(msg, pk1)
    print(
        "\x1b[1mWe have captured a message \x1b[0;92m{}\x1b[0;1m encrypted with the public key e = \x1b[0;92m{}\x1b[0;1m and N = \x1b[0;92m{}\x1b[0;1m.\x1b[0m".format(
            ct1, pk1.e, pk1.n
        )
    )
    ct2 = rsa_encrypt(msg, pk2)
    print(
        "\x1b[1mWe have captured a message \x1b[0;92m{}\x1b[0;1m encrypted with the public key e = \x1b[0;92m{}\x1b[0;1m and N = \x1b[0;92m{}\x1b[0;1m.\x1b[0m".format(
            ct2, pk2.e, pk2.n
        )
    )
    ct3 = rsa_encrypt(msg, pk3)
    print(
        "\x1b[1mWe have captured a message \x1b[0;92m{}\x1b[0;1m encrypted with the public key e = \x1b[0;92m{}\x1b[0;1m and N = \x1b[0;92m{}\x1b[0;1m.\x1b[0m".format(
            ct3, pk3.e, pk3.n
        )
    )

    ptx = rsa_broadcast_attack((ct1, pk1), (ct2, pk2), (ct3, pk3))
    print("\x1b[1mThe message is: \x1b[0;93m{}\x1b[0m".format(ptx))
