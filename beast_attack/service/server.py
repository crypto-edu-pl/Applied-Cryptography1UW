from sys import argv
from networking import TlsListener


def handle_client(stream):
    while True:
        request = stream.recvuntil(b"\r\n\r\n")
        if request is None:
            break

        print(request)

        stream.send(b"HTTP/2 204 No Content\r\n\r\n")


def main():
    try:
        host = argv[1]
        port = int(argv[2])
    except (IndexError, ValueError):
        print("Usage:", argv[0], "[HOST] [PORT]")
        return

    TlsListener.bind(host, port).accept(handle_client)


if __name__ == "__main__":
    main()
