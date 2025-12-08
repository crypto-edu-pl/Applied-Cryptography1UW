from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import string
import socket

BLOCK_SIZE = 16
KNOWN1 = b"GET /pub/"
KNOWN2 = b"HTTP/2\r\nCookie: Proxy-Key="
KNOWN3 = b"\r\nIdempotency-Key: "
HOST = "127.0.0.1"
PORT = 5000

def to_blocks(message):
    return [message[i:i+BLOCK_SIZE] for i in range(0, len(message), BLOCK_SIZE)]

def xor_first_block(data, xors):
    data = bytearray(data)
    for xor in xors:
        for i, b in enumerate(xor):
            data[i] ^= b
    return data

def send_and_get_response(message):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))     
        s.sendall(message)
        response = s.recv(4096)
        return response

def main():
    global PORT

    PORT = int(input("Enter port: "))

    infix = b"A" * (BLOCK_SIZE - ((len(KNOWN1) + len(KNOWN2)) % BLOCK_SIZE) - 1)
    secret_block_nr = (len(KNOWN1) + len(KNOWN2)) // BLOCK_SIZE
    guessed_secret = b""

    while guessed_secret[-2:] != b"\r\n":
        correct_ciphertext = send_and_get_response(infix)
        last_iv = correct_ciphertext[-BLOCK_SIZE:]
        iv_used = correct_ciphertext[(secret_block_nr - 1) * BLOCK_SIZE:secret_block_nr * BLOCK_SIZE]
        for letter in range(256):
            letter = bytes([letter])
            plaintext = (KNOWN1 + KNOWN2)[-BLOCK_SIZE + len(guessed_secret) + 1:] + guessed_secret + letter
            print(f"Checking {to_blocks(plaintext)}")
            ciphertext = send_and_get_response(xor_first_block(plaintext, [last_iv, iv_used]))
            last_iv = ciphertext[-BLOCK_SIZE:]
            if (ciphertext[:BLOCK_SIZE] == correct_ciphertext[secret_block_nr * BLOCK_SIZE:(secret_block_nr + 1) * BLOCK_SIZE]):
                guessed_secret = guessed_secret + letter
                infix = infix[:-1]
                print(letter)
                break
    print(guessed_secret[:-2])

if __name__ == "__main__":
    main()