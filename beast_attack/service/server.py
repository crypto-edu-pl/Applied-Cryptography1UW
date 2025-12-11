from sys import argv
from networking import TlsListener


def handle_client(stream):
    while True:
        request = stream.recvuntil(b"\r\n\r\n")
        if request is None:
            break

        lines = request.split(b"\r\n")
        start = lines[0]
        headers = lines[1:]

        path = start.rsplit(b" ", 1)[0].split(b" ", 1)[1]

        authorized = False
        for header in headers:
            if header == b"Proxy-Key: BLUESUBMARINE":
                authorized = True

        if not authorized:
            stream.send(b"HTTP/2 403 Forbidden\r\n\r\n")
            continue

        if path == b"/flag":
            stream.send(b"HTTP/2 200 flag{Hack the planet!}\r\n\r\n")
            continue

        stream.send(b"HTTP/2 404 Not Found\r\n\r\n")


def main():
    try:
        host = argv[1]
        port = int(argv[2])
    except (IndexError, ValueError):
        print("Usage:", argv[0], "[HOST] [PORT]")
        return

    TlsListener.bind(host, port, True).accept(handle_client)


if __name__ == "__main__":
    main()
