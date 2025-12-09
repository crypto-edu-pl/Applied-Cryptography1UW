from sys import argv
from socket import create_connection, create_server, AF_INET6
from threading import Thread
from struct import unpack
from binascii import hexlify


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


def show_data_packet(type, content):
    if type != 0x17:
        return

    # Argument `content` contains a 20 byte MAC at the end
    print(hexlify(content))


def main():
    try:
        catcher_host = argv[1]
        catcher_port = int(argv[2])
        target_host = argv[3]
        target_port = int(argv[4])
    except (IndexError, ValueError):
        print(
            "Usage:",
            argv[0],
            "[CATCHER HOST] [CATCHER PORT] [TARGET HOST] [TARGET PORT]",
        )
        return

    sniffer = Thread(
        target=run_sniffer,
        args=(
            show_data_packet,
            None,
            (catcher_host, catcher_port),
            (target_host, target_port),
        ),
    )
    sniffer.start()
    sniffer.join()


if __name__ == "__main__":
    main()
