from sys import argv
from networking import TlsStream
from Crypto.Random import get_random_bytes
from binascii import hexlify


def main():
    try:
        host = argv[1]
        port = int(argv[2])
        endpoint = argv[3]
    except (IndexError, ValueError):
        print("Usage:", argv[0], "[HOST] [PORT] [ENDPOINT]")
        return

    stream = TlsStream.connect(host, port)
    request = "GET /{} HTTP/2\r\n".format(endpoint)
    request += "Idempotency-Key: {}\r\n".format(hexlify(get_random_bytes(16)).decode())
    request += "\r\n"
    stream.send(request.encode())

    print(stream.recvuntil(b"\r\n\r\n").decode())


if __name__ == "__main__":
    main()
