"""Closed native fixture: verified TLS transport for one official asset URL."""
import pathlib
import socketserver
import ssl
import sys

asset, certificate, key, ready = map(pathlib.Path, sys.argv[1:])
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certificate, key)
target = b"GET /MetaCubeX/mihomo/releases/download/v1.19.33/mihomo-linux-amd64-v1.19.33.gz HTTP/1.1"


def header(stream):
    result = bytearray()
    while len(result) <= 65536:
        byte = stream.recv(1)
        if not byte:
            raise ValueError("truncated header")
        result += byte
        if result.endswith(b"\r\n\r\n"):
            return bytes(result)
    raise ValueError("oversized header")


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(15)
        try:
            if header(self.request).split(b"\r\n", 1)[0] != b"CONNECT github.com:443 HTTP/1.1":
                self.request.sendall(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n")
                return
            self.request.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            with context.wrap_socket(self.request, server_side=True) as connection:
                if header(connection).split(b"\r\n", 1)[0] != target:
                    connection.sendall(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
                    return
                connection.sendall(("HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: %d\r\n\r\n" % asset.stat().st_size).encode())
                with asset.open("rb") as source:
                    sent = 0
                    while block := source.read(128 * 1024):
                        connection.sendall(block)
                        sent += len(block)
                if sent == asset.stat().st_size:
                    ready.with_name("proxy-transfer-complete").write_text(str(sent) + "\n")
        except (OSError, ValueError):
            pass


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True


with Server(("127.0.0.1", 29499), Handler) as server:
    ready.write_text("ready\n")
    server.serve_forever(poll_interval=0.1)
