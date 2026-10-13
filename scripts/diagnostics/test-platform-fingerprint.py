#!/usr/bin/env python3
"""Portable collector/parser regressions; stdlib and local shell utilities only."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
DIRECTORY = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('platform_parser', DIRECTORY / 'compare-platforms.py')
PARSER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PARSER)


def elf_header(cls=1, order=1, machine=8):
    raw = bytearray(64)
    raw[:7] = b'\x7fELF' + bytes([cls, order, 1])
    endian = '<' if order == 1 else '>'
    struct.pack_into(endian + 'HHI', raw, 16, 2, machine, 1)
    struct.pack_into(endian + 'H', raw, 40 if cls == 1 else 52, 52 if cls == 1 else 64)
    return bytes(raw)


def elf_section(raw):
    return {'collector_exit_code': 0, 'text': 'path=/fixture\nheader_decimal_bytes:\n' +
            ' '.join(str(b) for b in raw) + '\nsha256=NOT_REQUESTED'}


def posix_path(path):
    value = Path(path).resolve().as_posix()
    if os.name == 'nt':
        value = re.sub(r'^([A-Za-z]):/', lambda m: '/' + m[1].lower() + '/', value)
    return value


class ParserTests(unittest.TestCase):
    def test_elf_byte_order_and_class_are_observed_only(self):
        for cls, order, machine, lane in [(1, 1, 8, 'MIPSEL'), (1, 2, 8, 'MIPS_BE'),
                                          (2, 1, 183, 'ARM64'), (2, 1, 62, 'AMD64_HOST')]:
            with self.subTest(lane=lane):
                result = PARSER.decode_elf(elf_section(elf_header(cls, order, machine)))
                self.assertEqual(result['architecture_lane'], lane)
                self.assertEqual(result['execution_status'], 'NOT_EXECUTED')
                self.assertEqual(result['full_abi_float_isa_and_dynamic_loader'], 'NOT_DETERMINED_FROM_THIS_HEADER')

    def test_malformed_and_truncated_headers_never_choose_lane(self):
        valid = elf_header()
        cases = [valid[:n] for n in (0, 4, 19, 20, 51)]
        cases += [b'bad!' + valid[4:], valid + b'\0', elf_header(2, 1, 183)[:63]]
        for offset, value in [(4, 0), (5, 0), (6, 2), (20, 2), (40, 0)]:
            changed = bytearray(valid)
            changed[offset] = value
            cases.append(bytes(changed))
        for raw in cases:
            with self.subTest(length=len(raw)):
                result = PARSER.decode_elf(elf_section(raw))
                self.assertIsNone(result['architecture_lane'])
                self.assertTrue(result['status'].startswith('UNKNOWN'))
        for text in ['256', '-1', '127 invalid 42', ' '.join(str(b) for b in valid) + '\nextra']:
            result = PARSER.decode_elf({'collector_exit_code': 0, 'text': 'header_decimal_bytes:\n' + text})
            self.assertIsNone(result['architecture_lane'])

    def test_failed_collection_cannot_supply_architecture(self):
        section = elf_section(elf_header(1, 2, 8))
        section['collector_exit_code'] = 1
        self.assertIsNone(PARSER.decode_elf(section)['architecture_lane'])
        self.assertIsNone(PARSER.decode_elf(None)['architecture_lane'])

    def test_framing_and_file_bounds(self):
        valid = 'KAFINGERPRINT|1\n@section|uname_machine\nmips\n@end|uname_machine|0\nKAFINGERPRINT_END|1\n'
        for broken in [valid.replace('KAFINGERPRINT_END|1', ''), valid.replace('|0\n', '|256\n'),
                       valid.replace('@end|uname_machine', '@end|wrong'), valid.replace('@section|uname_machine', '@section|bad|name'),
                       valid.replace('KAFINGERPRINT_END|1', '@section|uname_machine\nx\n@end|uname_machine|0\nKAFINGERPRINT_END|1')]:
            with self.assertRaises(ValueError):
                PARSER.parse_sections(broken)
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'input.txt'
            path.write_text(valid, encoding='utf-8')
            normalized = PARSER.normalize(path)
            self.assertIsNone(normalized['current_shell_elf']['architecture_lane'])
            self.assertTrue(all(v == 'UNKNOWN_NOT_TESTED' for v in normalized['functional_support'].values()))
            path.write_bytes(b'x' * (PARSER.MAX_INVENTORY_BYTES + 1))
            with self.assertRaises(ValueError):
                PARSER.normalize(path)

    def test_offline_cli_comparison_and_evidence_preservation(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            first, second = base / 'host.txt', base / 'router.txt'
            prefix = 'KAFINGERPRINT|1\n@section|shell_elf\n'
            suffix = '\n@end|shell_elf|0\nKAFINGERPRINT_END|1\n'
            first.write_text(prefix + elf_section(elf_header(1, 1, 8))['text'] + suffix, encoding='utf-8')
            second.write_text(prefix + elf_section(elf_header(1, 2, 8))['text'] + suffix, encoding='utf-8')
            command = [sys.executable, str(DIRECTORY / 'compare-platforms.py'), str(first), str(second)]
            result = subprocess.run(command, capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            comparison = json.loads(result.stdout)
            lane = next(row for row in comparison['differences'] if row['field'] == 'architecture_lane')
            self.assertEqual((lane['host'], lane['router'], lane['comparison']), ('MIPSEL', 'MIPS_BE', 'DIFFERENT_OBSERVATION'))
            original = first.read_bytes()
            result = subprocess.run(command + ['--output', str(first)], capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(first.read_bytes(), original)
            alias = base / 'alias.txt'
            os.link(first, alias)
            result = subprocess.run(command + ['--output', str(alias)], capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(first.read_bytes(), original)
            output = base / 'result.json'
            result = subprocess.run(command + ['--output', str(output)], capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(output.read_text())['evidence_level'], 'PASSIVE_COMPARISON')


class CollectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        chosen = os.environ.get('RAZVILKA_DIAG_TEST_SH')
        if not chosen and os.name == 'nt':
            chosen = str(Path(os.environ.get('ProgramFiles', 'C:/Program Files')) / 'Git/usr/bin/sh.exe')
        cls.shell = chosen or shutil.which('sh')
        if not cls.shell or not Path(cls.shell).is_file():
            raise RuntimeError('A local POSIX shell is required; no WSL fallback')
        tool_dir = Path(cls.shell).resolve().parent
        cls.tools = {}
        for name in ['awk', 'dd', 'od', 'sha256sum', 'tr']:
            candidate = tool_dir / (name + '.exe' if os.name == 'nt' else name)
            actual = str(candidate) if candidate.is_file() else shutil.which(name)
            if not actual:
                raise RuntimeError('Missing local regression dependency: ' + name)
            cls.tools[name] = actual

    def collect(self, profile='gnu', missing=None, dd_failure=False, malformed=False, raw=None):
        with tempfile.TemporaryDirectory(prefix='razvilka-diagnostics-') as temp:
            base = Path(temp)
            mocks = base / 'mocks'
            mocks.mkdir()
            audit = base / 'audit.txt'
            binary = base / 'engine with spaces.bin'
            data = (elf_header() if raw is None else raw) + b'\0' * 4096
            binary.write_bytes(data)
            if raw is not None:
                binary.write_bytes(raw)
                data = raw
            for name, actual in self.tools.items():
                if name == missing:
                    continue
                body = '#!/bin/sh\n'
                if name in ('dd', 'od', 'sha256sum'):
                    body += 'printf "%s|%s|%s|%s\\n" ' + shlex.quote(name) + ' "${1-}" "${2-}" "${3-}" >> "$DIAG_AUDIT"\n'
                if name == 'od' and profile == 'busybox-short':
                    body += '[ "$#" = 2 ] && [ "$1" = -b ] && [ "$2" = -v ] || exit 99\n'
                if name == 'od' and malformed:
                    body += "printf '0000000 999\\n0000001\\n'\nexit 0\n"
                elif name == 'dd' and dd_failure:
                    body += shlex.quote(posix_path(actual)) + ' "$@"\nexit 9\n'
                else:
                    body += 'exec ' + shlex.quote(posix_path(actual)) + ' "$@"\n'
                (mocks / name).write_text(body, encoding='utf-8', newline='\n')
                (mocks / name).chmod(0o700)
            for name, output in [('uname', 'mips'), ('date', '2026-10-13T00:00:00Z'), ('df', '')]:
                (mocks / name).write_text('#!/bin/sh\nprintf "%s\\n" ' + shlex.quote(output) + '\n', encoding='utf-8', newline='\n')
                (mocks / name).chmod(0o700)
            env = dict(os.environ, PATH=posix_path(mocks), DIAG_AUDIT=posix_path(audit))
            result = subprocess.run([self.shell, posix_path(DIRECTORY / 'collect-platform-fingerprint.sh'),
                                     '--binary', posix_path(binary)], env=env, capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stderr, '')
            path = base / 'fingerprint.txt'
            path.write_text(result.stdout, encoding='utf-8', newline='\n')
            parsed = PARSER.normalize(path)
            recorded = audit.read_text() if audit.exists() else ''
            self.assertTrue(all(v == 'UNKNOWN_NOT_TESTED' for v in parsed['functional_support'].values()))
            return parsed, recorded, hashlib.sha256(data).hexdigest()

    def test_short_busybox_and_gnu_real_byte_reader(self):
        for profile in ['gnu', 'busybox-short']:
            with self.subTest(profile=profile):
                parsed, audit, digest = self.collect(profile)
                binary = parsed['explicit_binary_headers']['binary_1']
                self.assertEqual(binary['architecture_lane'], 'MIPSEL')
                self.assertEqual(binary['sha256'], digest)
                self.assertEqual(binary['execution_status'], 'NOT_EXECUTED')
                self.assertTrue(all('bs=64|count=1' in line for line in audit.splitlines() if line.startswith('dd|')))
                self.assertTrue(all('od|-b|-v|' == line for line in audit.splitlines() if line.startswith('od|')))
                hashes = [line for line in audit.splitlines() if line.startswith('sha256sum|')]
                self.assertEqual(len(hashes), 1, 'Automatic shell image must not be hashed')
                self.assertIn('engine with spaces.bin', hashes[0])

    def test_missing_commands_preserve_unknown(self):
        for missing in ['od', 'dd']:
            with self.subTest(command=missing):
                parsed, audit, digest = self.collect(missing=missing)
                binary = parsed['explicit_binary_headers']['binary_1']
                self.assertIsNone(binary['architecture_lane'])
                self.assertEqual(binary['status'], 'UNKNOWN_NOT_COLLECTED')
                self.assertEqual(binary['sha256'], digest)
        parsed, audit, _ = self.collect(missing='sha256sum')
        self.assertEqual(parsed['explicit_binary_headers']['binary_1']['architecture_lane'], 'MIPSEL')
        self.assertIsNone(parsed['explicit_binary_headers']['binary_1']['sha256'])

    def test_failed_producer_and_malformed_od_cannot_be_masked(self):
        for options in [dict(dd_failure=True), dict(malformed=True)]:
            with self.subTest(options=options):
                parsed, _, _ = self.collect(**options)
                self.assertEqual(parsed['explicit_binary_headers']['binary_1']['status'], 'UNKNOWN_NOT_COLLECTED')
                self.assertIsNone(parsed['explicit_binary_headers']['binary_1']['architecture_lane'])

    def test_real_truncated_binary_header_is_unknown(self):
        parsed, _, _ = self.collect(raw=elf_header()[:19])
        self.assertEqual(parsed['explicit_binary_headers']['binary_1']['status'], 'UNKNOWN_INCOMPLETE_ELF_HEADER')
        self.assertIsNone(parsed['explicit_binary_headers']['binary_1']['architecture_lane'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
