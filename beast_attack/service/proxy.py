from sys import argv
from networking import TlsListener, TlsStream


def make_handle_client(server_host, server_port):
    def handle_client(client):
        server = TlsStream.connect(server_host, server_port)

        while True:
            start = client.recvuntil(b"\r\n")
            if start is None:
                break

            path = start.rsplit(b" ", 1)[0].split(b" ", 1)[1]

            server.send(
                b"GET /pub"
                + path
                + b" HTTP/2\r\nProxy-Key: BLUESUBMARINE\r\nIdempotency-Key: "
            )

            headers = client.recvuntil(b"\r\n\r\n")
            if headers is None:
                break

            idempotency_key = b"0" * 32

            for header in headers.split(b"\r\n"):
                if header.startswith(b"Idempotency-Key: "):
                    idempotency_key = header.split(b" ", 1)[1]

            server.send(idempotency_key + b"\r\n\r\n")

            response = server.recvuntil(b"\r\n\r\n")
            if response is None:
                break

            client.send(response + b"\r\n\r\n")

    return handle_client


def main():
    try:
        proxy_host = argv[1]
        proxy_port = int(argv[2])
        server_host = argv[3]
        server_port = int(argv[4])
    except (IndexError, ValueError):
        print(
            "Usage:",
            argv[0],
            "[PROXY HOST] [PROXY PORT] [SERVER HOST] [SERVER PORT]",
        )
        return

    TlsListener.bind(proxy_host, proxy_port).accept(
        make_handle_client(server_host, server_port)
    )


if __name__ == "__main__":
    main()
