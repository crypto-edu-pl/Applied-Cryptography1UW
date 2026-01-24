from Crypto.Hash import SHA256
from Crypto.Random.random import randint
from binascii import hexlify
from collections import namedtuple

DHGroup = namedtuple("DHGroup", "p g")

nist_group = DHGroup(
    p=0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF,
    g=0x2,
)


def dh_generate_key(group):
    sk = randint(2, group.p - 2)
    pk = pow(group.g, sk, group.p)
    return (pk, sk)


def dh_make_shared_secret(group, sk, pk):
    shared = pow(pk, sk, group.p)
    h = SHA256.new()
    h.update(str(shared).encode())
    h = h.digest()
    return h[:16], h[16:]


if __name__ == "__main__":
    print(
        "\x1b[1mThe DH group has parameters g = \x1b[0;92m{}\x1b[0;1m and p = \x1b[0;92m{}\x1b[0;1m.\x1b[0m".format(
            hex(nist_group.g), hex(nist_group.p)
        )
    )
    print("Generating your key pair...")
    pk_a, sk_a = dh_generate_key(nist_group)
    print("\x1b[1mYour secret key: \x1b[0;91m{}\x1b[0;1m".format(sk_a))
    print("\x1b[1mYour public key: \x1b[0;92m{}\x1b[0;1m".format(pk_a))
    print(
        "\x1b[92;1mYou can now share your public key and keep the secret one secret!\x1b[0m"
    )
    print(
        "\x1b[1mEnter the other public key (leave empty to generate a random other pair): \x1b[0m",
        end="",
    )
    pk_b = input()
    print("\x1b[1mYour shared secrets are:\x1b[0m")
    if pk_b == "":
        pk_b, sk_b = dh_generate_key(nist_group)
        enc_key_a, mac_key_a = dh_make_shared_secret(nist_group, sk_a, pk_b)
        enc_key_b, mac_key_b = dh_make_shared_secret(nist_group, sk_b, pk_a)
        print(
            "\x1b[1m                     Ours                              Theirs\x1b[0m"
        )
        print(
            "\x1b[1m     Encryption key: \x1b[93m{}\x1b[0;1m  \x1b[93m{}\x1b[0m".format(
                hexlify(enc_key_a).decode(), hexlify(enc_key_b).decode()
            )
        )
        print(
            "\x1b[1m Authentication key: \x1b[93m{}\x1b[0;1m  \x1b[93m{}\x1b[0m".format(
                hexlify(mac_key_a).decode(), hexlify(mac_key_b).decode()
            )
        )
    else:
        pk_b = int(pk_b)
        enc_key, mac_key = dh_make_shared_secret(nist_group, sk_a, pk_b)
        print(
            "\x1b[1m     Encryption key: \x1b[93m{}\x1b[0m".format(
                hexlify(enc_key).decode()
            )
        )
        print(
            "\x1b[1m Authentication key: \x1b[93m{}\x1b[0m".format(
                hexlify(mac_key).decode()
            )
        )

    print("\x1b[92;1mMake sure they match and happy hacking!\x1b[0m")
