from ssl import SSLContext, PROTOCOL_TLSv1
from socket import create_connection, create_server, AF_INET6
from threading import Thread

SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS = 2048


def build_ssl_context(keylog=False):
    tls = SSLContext(PROTOCOL_TLSv1)
    tls.set_ciphers("ECDHE-RSA-AES128-SHA@SECLEVEL=0")
    tls.options |= SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS
    if keylog:
        tls.keylog_filename = "keys.log"
    return tls


class TlsListener:
    def __init__(self, socket):
        self.__socket = socket

    def bind(host, port, keylog=False):
        tls = build_ssl_context(keylog)
        tls.load_cert_chain("pki/cert.pem", "pki/key.pem")
        socket = create_server((host, port), family=AF_INET6, reuse_port=True)
        wrapped = tls.wrap_socket(socket, server_side=True)
        return TlsListener(wrapped)

    def accept(self, handler):
        try:
            while True:
                socket, address = self.__socket.accept()
                Thread(target=handler, args=(TlsStream(socket, address),)).start()
        except BrokenPipeError:
            pass
        except KeyboardInterrupt:
            pass

    def __del__(self):
        self.__socket.close()


class TlsStream:
    def __init__(self, socket, address):
        self.__address = address
        self.__socket = socket
        self.__buffer = b""

    def connect(host, port, keylog=False):
        tls = build_ssl_context(keylog)
        tls.load_verify_locations("pki/cert.pem")
        socket = create_connection((host, port))
        wrapped = tls.wrap_socket(socket, server_hostname="beast.example")
        return TlsStream(wrapped, None)

    def send(self, data):
        try:
            self.__socket.sendall(data)
        except BrokenPipeError:
            pass

    def recvn(self, n):
        buffer = b""

        while n > 0:
            try:
                data = self.__socket.recv(n)
            except BrokenPipeError:
                return None

            if data == b"":
                return None

            buffer += data
            n -= len(data)

        return buffer

    def recvuntil(self, delim):
        while True:
            parts = self.__buffer.split(delim, 1)

            if len(parts) >= 2:
                self.__buffer = parts[1]
                return parts[0]
            else:
                self.__buffer = parts[0]

            try:
                data = self.__socket.recv(2**16)
            except BrokenPipeError:
                return None

            self.__buffer += data

    def __del__(self):
        try:
            self.__socket.close()
        except:
            pass
