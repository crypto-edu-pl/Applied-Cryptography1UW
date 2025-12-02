#!/usr/bin/env python3
import os
import socket
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad


HOST = "127.0.0.1"
PORT = 5000

SECRET_COOKIE = b"SESSIONID=67676767"
KEY = os.urandom(16)
IV = os.urandom(16)

BLOCK = 16


def tls10_encrypt_and_update_iv(plaintext: bytes) -> bytes:
    global IV

    msg = plaintext

    padded = pad(msg, BLOCK)

    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    ciphertext = cipher.encrypt(padded)

    IV = ciphertext[-BLOCK:]

    return ciphertext


def main():
    print(f"Listening on {HOST}:{PORT}")
    print("AES KEY =", KEY.hex())
    print("Initial IV =", IV.hex())

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen(1)

        while True:
            conn, _ = s.accept()
            with conn:
                data = conn.recv(4096)
                if not data:
                    continue

                print("Got:", data)
                ciphertext = tls10_encrypt_and_update_iv(data + SECRET_COOKIE)
                print("Sending:", ciphertext)
                conn.sendall(ciphertext)


if __name__ == "__main__":
    main()
