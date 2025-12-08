#!/usr/bin/env python3
import os
import socket
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad


HOST = "127.0.0.1"
PORT = 5000

BLOCK_SIZE = 16
SECRET_COOKIE = b"SECRET"
KEY = os.urandom(BLOCK_SIZE)
IV = os.urandom(BLOCK_SIZE)

KNOWN1 = b"GET /pub/"
KNOWN2 = b"HTTP/2\r\nCookie: Proxy-Key="
KNOWN3 = b"\r\nIdempotency-Key: "

def tls10_encrypt_and_update_iv(plaintext: bytes) -> bytes:
    global IV

    print(f"Encrypting: {plaintext}")

    padded = pad(plaintext, BLOCK_SIZE)

    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    ciphertext = cipher.encrypt(padded)

    IV = ciphertext[-BLOCK_SIZE:]

    return ciphertext


def main():
    global PORT

    PORT = int(input("Enter port: "))

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
                if data[0:3] == b"AAA":
                    data = KNOWN1 + data + KNOWN2 + SECRET_COOKIE + KNOWN3
                ciphertext = tls10_encrypt_and_update_iv(data)
                print("Sending:", ciphertext)
                conn.sendall(ciphertext)


if __name__ == "__main__":
    main()