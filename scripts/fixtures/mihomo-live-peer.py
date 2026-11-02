#!/usr/bin/python3
"""Disposable physical TLS/VLESS peer only; no RAZVILKA controller API."""
import http.server
import ctypes
import json
import os
import pathlib
import signal
import socket
import ssl
import subprocess
import threading
import time

root = pathlib.Path(os.environ["RAZVILKA_DOMAIN_NATIVE_ROOT"])
binary = pathlib.Path(os.environ["RAZVILKA_XRAY_NATIVE"])
socket.setdefaulttimeout(3)
if os.geteuid() != 0 or not root.is_absolute() or not binary.is_absolute():
    raise SystemExit("isolated original physical peer required")


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        source, port = self.client_address
        # Error-only physical fixture seam. The test authors this fixed file
        # only AFTER its actual configuration CAS. It cannot fabricate a
        # controller result, alter TLS/routing, or authorize any resource.
        degraded = (self.path == "/" and self.headers.get("Host") == "service.example.com"
                    and (root / "mihomo-service-degraded").exists())
        body = json.dumps({"Source": source, "SourcePort": str(port),
                           "Marker": "native-domain-service"}).encode()
        if self.path == "/cdn-cgi/trace":
            body = ("ip=" + source + "\nwarp=off\n").encode()
        elif self.headers.get("Host") == "api.ipify.org":
            body = source.encode()
        self.send_response(503 if degraded else 200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        self.wfile.flush()
        if degraded:
            event = json.dumps({"Host": "service.example.com", "Status": 503,
                                "Source": source, "Marker": "physical-error-after-cas"}).encode() + b"\n"
            fd = os.open(root / "mihomo-service-degraded-observed",
                         os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            try:
                if os.fstat(fd).st_size > 8192:
                    raise RuntimeError("bounded physical failure evidence exceeded")
                os.write(fd, event)
            finally:
                os.close(fd)

    def log_message(self, *_):
        pass


config = {
    "log": {"loglevel": "debug", "access": "none"},
    "dns": {"hosts": {name: "1.1.1.2" for name in
                      ("service.example.com", "unknown.example.com", "www.cloudflare.com", "api.ipify.org")}},
    "inbounds": [{"listen": "1.1.1.2", "port": 10443, "protocol": "vless",
                  "settings": {"clients": [{"id": "123e4567-e89b-12d3-a456-426614174000"}],
                               "decryption": "none"},
                  "streamSettings": {"network": "tcp", "security": "tls",
                                     "tlsSettings": {"certificates": [{"certificateFile": str(root / "ca.pem"),
                                                                         "keyFile": str(root / "key.pem")}]}}}],
    "outbounds": [{"protocol": "freedom", "sendThrough": "1.1.1.2",
                   "settings": {"domainStrategy": "UseIPv4"}}],
}
path = root / "mihomo-physical-xray.json"
path.write_text(json.dumps(config))
path.chmod(0o600)
done = threading.Event()
signal.signal(signal.SIGTERM, lambda *_: done.set())
signal.signal(signal.SIGINT, lambda *_: done.set())
log = (root / "mihomo-physical-xray.log").open("wb")
# Popen occurs before any helper thread exists. Bind the actual child to this
# original parent, including the fork/prctl parent-death race.
parent_pid = os.getpid()
libc = ctypes.CDLL(None, use_errno=True)
libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
libc.prctl.restype = ctypes.c_int


def child_parent_death():
    if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0:
        os._exit(126)
    if os.getppid() != parent_pid:
        os.kill(os.getpid(), signal.SIGKILL)


child = None
server = None
thread = None
try:
    child = subprocess.Popen([str(binary), "run", "-config", str(path)],
                             stdout=log, stderr=log, preexec_fn=child_parent_death)
    server = http.server.ThreadingHTTPServer(("1.1.1.2", 443), Handler)
    server.daemon_threads = True
    server.block_on_close = False
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(root / "ca.pem", root / "key.pem")
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    deadline = time.monotonic() + 5
    while True:
        if done.is_set():
            raise RuntimeError("physical peer canceled before readiness")
        if child.poll() is not None:
            raise RuntimeError("official physical VLESS peer exited")
        try:
            with socket.create_connection(("1.1.1.2", 10443), timeout=0.1):
                break
        except OSError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.02)
    (root / "server.ready").write_text("physical TLS/VLESS peer ready\n")
    while not done.wait(0.1):
        if child.poll() is not None:
            raise RuntimeError("official physical VLESS peer exited")
finally:
    # Stop/reap the exact Popen child first; this bound plus HTTP shutdown stays
    # inside the Go fixture's 8s grace. Forced parent death also kills this child.
    if child is not None:
        if child.poll() is None:
            child.terminate()
        try:
            child.wait(timeout=1)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait(timeout=1)
    if server is not None:
        if thread is not None:
            server.shutdown()
        server.server_close()
    if thread is not None:
        thread.join(timeout=0.5)
    log.close()
