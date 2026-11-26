"""Pinned, loopback-only component lab; not RAZVILKA route/LAN acceptance."""
import argparse
import hashlib
import json
import socket
import struct
import subprocess
import tempfile
import threading
import time
import urllib.request
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def port():
    # Bind-to-zero then close leaves a handoff race. Any bind/readiness failure
    # refuses the run; this observation grants no authority over ambient PIDs.
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def connect(number):
    return socket.create_connection(('127.0.0.1', number), timeout=1.5)


def wait(number, child):
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        if child.poll() is not None:
            raise RuntimeError('child-exited')
        try:
            with connect(number):
                return
        except OSError:
            time.sleep(.02)
    raise RuntimeError('listener-deadline')


def exact(sock, count):
    value = b''
    while len(value) < count:
        part = sock.recv(count - len(value))
        if not part:
            raise RuntimeError('unexpected-eof')
        value += part
    return value


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'razvilka-controlled-body')

    def log_message(self, *args):
        pass


def probe(client_port, http_port):
    with connect(client_port) as sock:
        sock.sendall(b'\x05\x01\x00')
        if exact(sock, 2) != b'\x05\x00':
            return False
        sock.sendall(b'\x05\x01\x00\x01' + socket.inet_aton('127.0.0.1') + struct.pack('!H', http_port))
        head = exact(sock, 4)
        if head[1] != 0:
            return False
        if head[3] == 1:
            exact(sock, 6)
        elif head[3] == 4:
            exact(sock, 18)
        elif head[3] == 3:
            exact(sock, exact(sock, 1)[0] + 2)
        else:
            return False
        sock.sendall(b'GET / HTTP/1.0\r\nHost: localhost\r\n\r\n')
        data = b''
        deadline = time.monotonic() + 1.5
        while time.monotonic() < deadline:
            sock.settimeout(max(.001, deadline - time.monotonic()))
            part = sock.recv(4096)
            if not part:
                break
            data += part
            if len(data) > 65536:
                return False
            if b'razvilka-controlled-body' in data:
                break
        return b'200 OK' in data and b'razvilka-controlled-body' in data


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--xray', required=True)
    parser.add_argument('--toxiproxy', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    report = {
        'scope': 'Windows loopback native Xray VLESS TCP + Toxiproxy; HTTP body; NOT TLS, ExactNodeChecker, router or LAN evidence',
        'rows': [], 'finished': False, 'failure_code': '',
        'listeners_closed': False, 'owned_processes_reaped': 0,
        'binaries': {},
    }
    processes, ports = [], []
    temporary = None
    server, server_thread = None, None
    scenario = 'preparation'
    try:
        for name, path, commit in [
            ('xray', args.xray, 'af8f9673afe8533390e0200637ad30508de803a5'),
            ('toxiproxy', args.toxiproxy, '49299d8838525126e09c85ebe0ba89940a3261e5'),
        ]:
            report['binaries'][name] = {
                'sha256': hashlib.sha256(Path(path).read_bytes()).hexdigest(),
                'expected_source_commit': commit,
            }
        report['xray_version'] = subprocess.check_output([args.xray, 'version'], timeout=5).decode().splitlines()[0]
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()
        http_port = server.server_port
        ports.append(http_port)
        identity = '11111111-1111-4111-8111-111111111111'
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        temporary = tempfile.TemporaryDirectory(prefix='razvilka-loopback-')
        tmp = temporary.name
        def start(arguments, number):
            started = time.monotonic()
            child = subprocess.Popen(arguments, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            processes.append(child)
            ports.append(number)
            wait(number, child)
            return round((time.monotonic() - started) * 1000, 3)

        def xray(name, config, number):
            path = Path(tmp) / (name + '.json')
            path.write_text(json.dumps(config))
            return start([args.xray, 'run', '-config', str(path)], number)

        vless_port, toxic_port, api_port = port(), port(), port()
        xray('server', {
            'log': {'loglevel': 'none'},
            'inbounds': [{'listen': '127.0.0.1', 'port': vless_port, 'protocol': 'vless', 'settings': {'clients': [{'id': identity}], 'decryption': 'none'}}],
            'outbounds': [{'protocol': 'freedom', 'settings': {'finalRules': [{'action': 'allow', 'network': 'tcp', 'ip': ['127.0.0.1/32'], 'port': str(http_port)}]}}],
        }, vless_port)
        start([args.toxiproxy, '-host', '127.0.0.1', '-port', str(api_port)], api_port)

        def request(path, data):
            req = urllib.request.Request(f'http://127.0.0.1:{api_port}' + path, data=json.dumps(data).encode(), headers={'Content-Type': 'application/json'})
            with opener.open(req, timeout=2) as response:
                return response.read(65537)

        request('/proxies', {'name': 'vless', 'listen': f'127.0.0.1:{toxic_port}', 'upstream': f'127.0.0.1:{vless_port}'})
        ports.append(toxic_port)
        for scenario, user_id in [('valid', identity), ('wrong-credentials', '22222222-2222-4222-8222-222222222222'), ('latency-100ms', identity)]:
            if scenario == 'latency-100ms':
                request('/proxies/vless/toxics', {'name': 'latency', 'type': 'latency', 'stream': 'downstream', 'attributes': {'latency': 100, 'jitter': 0}})
            client_port = port()
            ready = xray(scenario, {
                'log': {'loglevel': 'none'},
                'inbounds': [{'listen': '127.0.0.1', 'port': client_port, 'protocol': 'socks', 'settings': {'auth': 'noauth', 'udp': False}}],
                'outbounds': [{'protocol': 'vless', 'settings': {'vnext': [{'address': '127.0.0.1', 'port': toxic_port, 'users': [{'id': user_id, 'encryption': 'none'}]}]}}],
            }, client_port)
            for sample in range(4):
                started = time.monotonic()
                with connect(toxic_port):
                    tcp_open = True
                try:
                    passed = probe(client_port, http_port)
                except (OSError, RuntimeError):
                    passed = False
                report['rows'].append({
                    'scenario': scenario, 'sample': sample,
                    'phase': 'cold-client-first-request' if sample == 0 else 'repeated-same-client',
                    'tcp_open': tcp_open, 'service_body_pass': passed,
                    'request_ms': round((time.monotonic() - started) * 1000, 3),
                    'client_ready_ms': ready if sample == 0 else None,
                })
                if passed != (scenario != 'wrong-credentials'):
                    raise RuntimeError('unexpected-service-outcome')
        report['finished'] = True
    except Exception:
        report['finished'] = False
        # No paths, raw errors, logs, or profile material enter the safe report.
        report['failure_code'] = 'component-lab-failed'
        report['failure_scenario'] = scenario
    finally:
        started = time.monotonic()
        cleanup_ok = True
        for child in reversed(processes):
            try:
                if child.poll() is None:
                    child.terminate()
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=5)
                report['owned_processes_reaped'] += 1
            except Exception:
                cleanup_ok = False
        if server is not None:
            try:
                server.shutdown()
                server.server_close()
                server_thread.join(timeout=2)
                cleanup_ok = cleanup_ok and not server_thread.is_alive()
            except Exception:
                cleanup_ok = False
        for number in ports:
            try:
                with socket.create_connection(('127.0.0.1', number), timeout=3.5):
                    cleanup_ok = False
            except ConnectionRefusedError:
                pass
            except OSError:
                # A timeout/other error is not proof that the listener is closed.
                cleanup_ok = False
        report['cleanup_ms'] = round((time.monotonic() - started) * 1000, 3)
        if temporary is not None and report['owned_processes_reaped'] != len(processes):
            # Preserve config/state for any owned child whose exit was not proved.
            temporary._finalizer.detach()
            report['temporary_workspace_removed'] = False
            cleanup_ok = False
        elif temporary is not None:
            try:
                temporary.cleanup()
                report['temporary_workspace_removed'] = True
            except Exception:
                cleanup_ok = False
                report['temporary_workspace_removed'] = False
        report['listeners_closed'] = cleanup_ok
        if not cleanup_ok:
            report['finished'] = False
            report['failure_code'] = 'cleanup-unconfirmed'
    Path(args.output).write_text(json.dumps(report, indent=2))
    print(json.dumps(report))
    return 0 if report['finished'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
