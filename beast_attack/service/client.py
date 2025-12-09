from sys import argv

from networking import TlsStream


def main():
    try:
        host = argv[1]
        port = int(argv[2])
    except (IndexError, ValueError):
        print("Usage:", argv[0], "[HOST] [PORT]")
        return

    stream = TlsStream.connect(host, port)
    stream.send(b"GET / HTTP/2\r\n\r\n")


if __name__ == "__main__":
    main()
