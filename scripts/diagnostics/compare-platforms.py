#!/usr/bin/env python3
"""Parse passive inventory or compare host/router observations. Standard library only.

This tool does not contact a router, execute an inspected program, or certify
functional support. CPU/kernel/tool differences are observations, not diagnoses.

Adapted from supplied RAZVILKA_KEENETIC_CODEX_2026_10_12 materials; see README.md
for the source/archive SHA256. No architecture is inferred from uname/tool names.
"""
from pathlib import Path
import argparse
import hashlib
import json
import re
import struct
import sys

MAX_INVENTORY_BYTES = 1 << 20


def parse_sections(text):
    rows = text.splitlines()
    if not rows or rows[0] != 'KAFINGERPRINT|1':
        raise ValueError('Unsupported or missing fingerprint header')
    if not rows or rows[-1] != 'KAFINGERPRINT_END|1':
        raise ValueError('Incomplete fingerprint: no final marker')
    sections = {}
    current = None
    buffer = []
    for line in rows[1:-1]:
        if line.startswith('@section|'):
            if current is not None:
                raise ValueError('Nested or unterminated section')
            current = line.split('|', 1)[1]
            if not re.fullmatch(r'[a-z][a-z0-9_]{0,63}', current) or len(sections) >= 128:
                raise ValueError('Invalid section name or too many sections')
            if current in sections:
                raise ValueError('Duplicate section: ' + current)
            buffer = []
        elif line.startswith('@end|'):
            parts = line.split('|')
            if len(parts) != 3 or current != parts[1]:
                raise ValueError('Mismatched section terminator')
            if not re.fullmatch(r'0|[1-9][0-9]{0,2}', parts[2]) or int(parts[2]) > 255:
                raise ValueError('Invalid collector exit code')
            rc = int(parts[2])
            sections[current] = {
                'collector_exit_code': rc,
                'observation_status': 'COLLECTED' if rc == 0 else 'NOT_COLLECTED',
                'text': '\n'.join(buffer).strip(),
            }
            current = None
        elif current is not None:
            buffer.append(line)
        elif line.strip():
            raise ValueError('Unexpected data outside a section')
    if current is not None:
        raise ValueError('Unterminated section')
    return sections


def decode_elf(section):
    text = section['text'] if section else ''
    digest = re.search(r'^sha256=([0-9a-f]{64})$', text, re.M)
    path = re.search(r'^path=(.*)$', text, re.M)
    base = {'architecture_lane': None, 'path': path.group(1) if path else None,
            'sha256': digest.group(1) if digest else None,
            'execution_status': 'NOT_EXECUTED'}
    def unknown(status):
        return dict(base, status=status)
    if not section or section['collector_exit_code'] != 0:
        return unknown('UNKNOWN_NOT_COLLECTED')
    if text.splitlines().count('header_decimal_bytes:') != 1:
        return unknown('UNKNOWN_MISSING_OR_DUPLICATE_HEADER')
    header = text.split('header_decimal_bytes:\n', 1)
    if len(header) != 2:
        return unknown('UNKNOWN_INCOMPLETE_ELF_HEADER')
    data_lines = []
    suffix = False
    for line in header[1].splitlines():
        if not line.strip():
            continue
        if re.fullmatch(r'[0-9]+(?:[ \t]+[0-9]+)*', line.strip()) and not suffix:
            data_lines.extend(int(v) for v in line.split())
            if len(data_lines) > 64 or any(v > 255 for v in data_lines):
                return unknown('UNKNOWN_MALFORMED_ELF_HEADER_BYTES')
        elif re.fullmatch(r'sha256=(?:[0-9a-f]{64}|NOT_COLLECTED|NOT_REQUESTED)', line) and not suffix:
            suffix = True
        else:
            return unknown('UNKNOWN_MALFORMED_ELF_HEADER_BYTES')
    raw = bytes(data_lines)
    if len(raw) < 20:
        return unknown('UNKNOWN_INCOMPLETE_ELF_HEADER')
    if raw[:4] != b'\x7fELF':
        return unknown('UNKNOWN_NOT_ELF')
    cls, byte_order = raw[4], raw[5]
    if cls not in (1, 2) or byte_order not in (1, 2):
        return unknown('UNKNOWN_INVALID_ELF_CLASS_OR_DATA')
    size = 52 if cls == 1 else 64
    if len(raw) < size:
        return unknown('UNKNOWN_INCOMPLETE_ELF_HEADER')
    endian = '<' if byte_order == 1 else '>'
    version = struct.unpack_from(endian + 'I', raw, 20)[0]
    header_size = struct.unpack_from(endian + 'H', raw, 40 if cls == 1 else 52)[0]
    if raw[6] != 1 or version != 1 or header_size != size:
        return unknown('UNKNOWN_INVALID_ELF_HEADER_VERSION_OR_SIZE')
    machine = struct.unpack_from(endian + 'H', raw, 18)[0]
    flags = struct.unpack_from(endian + 'I', raw, 36 if cls == 1 else 48)[0]
    lane = {
        (1, 2, 8): 'MIPS_BE',
        (1, 1, 8): 'MIPSEL',
        (2, 1, 183): 'ARM64',
        (2, 1, 62): 'AMD64_HOST',
        (1, 1, 3): 'X86_32_HOST',
    }.get((cls, byte_order, machine), 'OTHER_ELF_TARGET')
    return dict(base, **{
        'status': 'OBSERVED_ELF_HEADER',
        'architecture_lane': lane,
        'elf_class_bits': 32 if cls == 1 else 64,
        'endianness': 'little' if byte_order == 1 else 'big',
        'elf_machine': machine,
        'elf_flags_hex': hex(flags),
        'full_abi_float_isa_and_dynamic_loader': 'NOT_DETERMINED_FROM_THIS_HEADER',
        'execution_status': 'NOT_EXECUTED',
    })


def normalize(path):
    with Path(path).open('rb') as source:
        raw = source.read(MAX_INVENTORY_BYTES + 1)
    if len(raw) > MAX_INVENTORY_BYTES:
        raise ValueError('Fingerprint exceeds 1 MiB limit')
    sections = parse_sections(raw.decode('utf-8'))
    def value(name):
        s = sections.get(name)
        return s['text'] if s and s['collector_exit_code'] == 0 else None
    elf = decode_elf(sections.get('shell_elf'))
    binaries = {name: decode_elf(s) for name, s in sections.items() if re.fullmatch(r'binary_\d+', name)}
    mismatches = []
    for name, binary in binaries.items():
        if elf['status'] == 'OBSERVED_ELF_HEADER' and binary['status'] == 'OBSERVED_ELF_HEADER':
            fields = ['elf_class_bits', 'endianness', 'elf_machine', 'elf_flags_hex']
            changed = {k: {'shell': elf[k], 'binary': binary[k]}
                       for k in fields if binary[k] != elf[k]}
            if changed:
                mismatches.append({
                    'binary': name, 'kind': 'ELF_HEADER_DIFFERS_FROM_CURRENT_SHELL',
                    'observed_differences': changed,
                    'note': 'Flags may encode different ABI/ISA details. The family lane is not a full ABI selector; use readelf on the exact artifact. A compatibility personality is not assumed. These differences do not prove runtime incompatibility.',
                })
    return {
        'schema_version': '1.0',
        'source_sha256': hashlib.sha256(raw).hexdigest(),
        'evidence_level': 'PASSIVE_INVENTORY',
        'collected_at_utc': value('collected_at_utc'),
        'declared_model': value('declared_model'),
        'declared_firmware': value('declared_firmware'),
        'declared_metadata_verified': False,
        'kernel': {'os': value('kernel_os'), 'release': value('kernel_release'), 'uname_machine': value('uname_machine')},
        'current_shell_elf': elf,
        'explicit_binary_headers': binaries,
        'binary_header_differences': mismatches,
        'observations': sections,
        'functional_support': {key: 'UNKNOWN_NOT_TESTED' for key in [
            'TUN_IOCTL', 'NETNS_CREATE_MOVE', 'NFQUEUE_BIND_VERDICT',
            'TPROXY_TCP', 'TPROXY_UDP', 'REDIRECT_ORIGINAL_DST',
            'POLICY_ROUTING_IPV4', 'POLICY_ROUTING_IPV6',
            'WIREGUARD_KERNEL', 'WIREGUARD_USERSPACE', 'AMNEZIAWG_PROTOCOL',
            'NDM_REBUILD_RECOVERY', 'OFFLOAD_INTERACTION',
            'SELECTED_LAN_PATH', 'EXCLUSIONS', 'H2', 'H3', 'UDP', 'MEDIA',
        ]},
        'interpretation': [
            'Current shell ELF is stronger evidence of its byte order than a generic uname string.',
            'architecture_lane identifies only class/machine/byte order; it does not establish o32 versus n32 or the complete float ABI/ISA.',
            'UNKNOWN / NOT_COLLECTED / missing file / missing command in PATH is not UNSUPPORTED.',
            'Loaded modules, device nodes, CONFIG and tool versions do not prove successful packet forwarding.',
            'getconf describes the resolved utility environment, not every engine or its dynamic interpreter.',
            'No network calls, engine launches or functional acceptance were performed by the collector.',
        ],
    }


def compare(left, right):
    fields = [
        ('architecture_lane', left['current_shell_elf'].get('architecture_lane'), right['current_shell_elf'].get('architecture_lane')),
        ('shell_elf_flags', left['current_shell_elf'].get('elf_flags_hex'), right['current_shell_elf'].get('elf_flags_hex')),
        ('kernel_release', left['kernel']['release'], right['kernel']['release']),
    ]
    for key in ['cpuinfo', 'memory', 'opkg_architecture', 'official_entware_feeds',
                'ip_version', 'iptables_version', 'ip6tables_version', 'nft_version',
                'curl_features', 'resolved_getconf_libc', 'primitive_presence',
                'kernel_config_subset', 'mount_metadata', 'storage_capacity']:
        def observation(item):
            s = item['observations'].get(key)
            return s['text'] if s and s['collector_exit_code'] == 0 else None
        fields.append((key, observation(left), observation(right)))
    rows = [{'field': k, 'host': a, 'router': b,
             'comparison': 'UNKNOWN' if a is None or b is None else ('SAME_OBSERVATION' if a == b else 'DIFFERENT_OBSERVATION')}
            for k, a, b in fields]
    return {
        'schema_version': '1.0', 'evidence_level': 'PASSIVE_COMPARISON',
        'host_inventory': left, 'router_inventory': right,
        'differences': rows,
        'conclusion': 'Differences guide capability and datapath checks; they are not an automatic root-cause diagnosis or router PASS.',
        'next_step': 'Verify the exact artifact and selected engine path with the relevant project acceptance, under the router mutation owner.',
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('host_or_inventory', type=Path)
    ap.add_argument('router_inventory', nargs='?', type=Path)
    ap.add_argument('--output', type=Path)
    args = ap.parse_args()
    first = normalize(args.host_or_inventory)
    result = compare(first, normalize(args.router_inventory)) if args.router_inventory else first
    text = json.dumps(result, ensure_ascii=False, indent=2) + '\n'
    if args.output:
        if args.output.resolve() in {args.host_or_inventory.resolve(), args.router_inventory.resolve() if args.router_inventory else None}:
            ap.error('Output must not overwrite an input fingerprint')
        # Never overwrite retained evidence, including a differently named
        # hard link. Exclusive creation also rejects an existing symlink.
        with args.output.open('x', encoding='utf-8', newline='\n') as output:
            output.write(text)
        print(str(args.output.resolve()))
    else:
        print(text, end='')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError) as exc:
        print('Inventory parsing failed: ' + str(exc), file=sys.stderr)
        sys.exit(2)
