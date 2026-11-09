"""Mihomo /delay versus strict status through the same native VLESS outbound."""
import argparse
import hashlib
import http.client
import json
import socket
import subprocess
import tempfile
import threading
import time
import urllib.parse
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from lab_loopback import port, wait


class StatusHandler(BaseHTTPRequestHandler):
    def respond(self):
        code = 204 if self.path == '/healthy' else 503
        self.send_response(code)
        self.send_header('Content-Length', '0')
        self.end_headers()

    do_GET = respond
    do_HEAD = respond

    def log_message(self, *args):
        pass


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--mihomo', required=True)
    parser.add_argument('--xray', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    report = {'scope': 'Windows loopback Mihomo VLESS TCP: API delay vs HTTP status204; no TLS, RAZVILKA selection, LAN or router claim', 'rows': [], 'finished': False, 'failure_code': '', 'owned_processes_reaped': 0, 'listeners_closed': False}
    processes, ports = [], []
    temporary = None
    server = thread = None
    try:
        report['binary_sha256'] = {name: hashlib.sha256(Path(path).read_bytes()).hexdigest() for name, path in [('mihomo', args.mihomo), ('xray', args.xray)]}
        report['mihomo_version'] = subprocess.check_output([args.mihomo, '-v'], timeout=5).decode().strip()
        report['source_commit'] = '3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8'
        server = ThreadingHTTPServer(('127.0.0.1', 0), StatusHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        http_port, vless_port, api_port, mixed_port = server.server_port, port(), port(), port()
        ports.append(http_port)
        temporary = tempfile.TemporaryDirectory(prefix='razvilka-mihomo-')
        tmp = temporary.name
        def launch(command, number):
            child = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            processes.append(child)
            ports.append(number)
            wait(number, child)
        identity = '11111111-1111-4111-8111-111111111111'
        path = Path(tmp) / 'xray.json'
        path.write_text(json.dumps({'log': {'loglevel': 'none'}, 'inbounds': [{'listen': '127.0.0.1', 'port': vless_port, 'protocol': 'vless', 'settings': {'clients': [{'id': identity}], 'decryption': 'none'}}], 'outbounds': [{'protocol': 'freedom', 'settings': {'finalRules': [{'action': 'allow', 'network': 'tcp', 'ip': ['127.0.0.1/32'], 'port': str(http_port)}]}}]}))
        launch([args.xray, 'run', '-config', str(path)], vless_port)
        config = Path(tmp) / 'config.yaml'
        # JSON is a YAML subset. No DNS/TUN/firewall/system proxy setup.
        config.write_text(json.dumps({'mixed-port': mixed_port, 'bind-address': '127.0.0.1', 'allow-lan': False, 'mode': 'rule', 'log-level': 'silent', 'external-controller': f'127.0.0.1:{api_port}', 'geo-auto-update': False, 'dns': {'enable': False}, 'tun': {'enable': False}, 'proxies': [{'name': 'fixture-vless', 'type': 'vless', 'server': '127.0.0.1', 'port': vless_port, 'uuid': identity, 'network': 'tcp', 'tls': False, 'udp': False}], 'rules': ['MATCH,fixture-vless']}))
        started = time.monotonic()
        launch([args.mihomo, '-d', tmp, '-f', str(config)], api_port)
        ports.append(mixed_port)
        wait(mixed_port, processes[-1])
        report['controller_and_listener_ready_ms'] = round((time.monotonic() - started) * 1000, 3)

        def api(path):
            conn = http.client.HTTPConnection('127.0.0.1', api_port, timeout=3)
            try:
                conn.request('GET', path)
                response = conn.getresponse()
                body = response.read(65537)
                if len(body) > 65536:
                    raise RuntimeError('api-size')
                return response.status, json.loads(body)
            finally:
                conn.close()

        for scenario in ['healthy', 'unavailable']:
            url = f'http://127.0.0.1:{http_port}/{scenario}'
            query = urllib.parse.urlencode({'url': url, 'timeout': 2000, 'expected': '204'})
            for sample in range(3):
                started = time.monotonic()
                api_status, data = api('/proxies/fixture-vless/delay?' + query)
                _, state = api('/proxies/fixture-vless')
                conn = http.client.HTTPConnection('127.0.0.1', mixed_port, timeout=2)
                try:
                    # Explicit absolute-form request prevents ambient localhost bypass.
                    conn.request('GET', url)
                    response = conn.getresponse()
                    strict_status = response.status
                    body = response.read(65537)
                    if len(body) > 65536:
                        raise RuntimeError('body-size')
                finally:
                    conn.close()
                url_state = state.get('extra', {}).get(url, {})
                row = {'scenario': scenario, 'sample': sample, 'api_status': api_status, 'delay_ms': data.get('delay'), 'global_alive': state.get('alive'), 'url_alive': url_state.get('alive'), 'strict_http_status': strict_status, 'strict_pass': strict_status == 204, 'wall_ms': round((time.monotonic() - started) * 1000, 3)}
                report['rows'].append(row)
                if api_status != 200 or data.get('delay', 0) <= 0 or row['strict_pass'] != (scenario == 'healthy') or row['url_alive'] != (scenario == 'healthy'):
                    raise RuntimeError('unexpected-outcome')
        report['finished'] = True
    except Exception:
        report['finished'] = False
        report['failure_code'] = 'mihomo-lab-failed'
    finally:
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
        if server:
            try:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)
                cleanup_ok = cleanup_ok and not thread.is_alive()
            except Exception:
                cleanup_ok = False
        for number in ports:
            try:
                with socket.create_connection(('127.0.0.1', number), timeout=3.5):
                    cleanup_ok = False
            except ConnectionRefusedError:
                pass
            except OSError:
                cleanup_ok = False
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
