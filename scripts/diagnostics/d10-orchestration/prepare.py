#!/usr/bin/env python3
"""Offline, private D10 input preparation. Never runs processes or networking."""
import argparse
import copy
import hashlib
import ipaddress
import json
import os
import pathlib
import re
import shlex
import stat
import sys
import urllib.parse
import uuid

PREFIX = "RAZVILKA_NATIVE_XRAY_AUTO_"
PHASES = {"FAULT_A": "applied_a", "PUBLISHED_C": "exhausted_ab", "STOP": "committed_c"}


class Refused(Exception):
    pass


def require(ok, code):
    if not ok:
        raise Refused(code)


def unique_object(pairs):
    out = {}
    for key, value in pairs:
        require(key not in out, "duplicate_json_field")
        out[key] = value
    return out


def decode(raw):
    return json.loads(raw, object_pairs_hook=unique_object)


def encode(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical_path(value):
    require(isinstance(value, str) and value.startswith("/") and
            str(pathlib.PurePosixPath(value)) == value and
            ".." not in pathlib.PurePosixPath(value).parts and
            not any(c in value for c in "\x00\r\n\t"), "canonical_posix_path_required")
    return value


def public4(value):
    address = ipaddress.ip_address(value)
    require(address.version == 4 and address.is_global, "public_ipv4_required")
    return str(address)


def material(raw):
    doc = decode(raw)
    require(isinstance(doc, dict) and set(doc) == {"outbounds"} and
            isinstance(doc["outbounds"], list) and len(doc["outbounds"]) == 1,
            "one_canonical_outbound_required")
    out = doc["outbounds"][0]
    require(isinstance(out, dict) and out.get("type") == "vless", "vless_required")
    address = public4(out.get("server"))
    port = out.get("server_port")
    require(type(port) is int and 1 <= port <= 65535, "finite_peer_port_required")
    require(str(uuid.UUID(out.get("uuid"))) == out["uuid"], "canonical_peer_identity_required")
    require(out.get("network", "tcp") == "tcp" and not out.get("transport"), "plain_tcp_transport_required")
    tls = out.get("tls")
    require(isinstance(tls, dict) and tls.get("enabled") is True and not tls.get("insecure"), "normal_peer_tls_required")
    return copy.deepcopy(out), (address, port, "tcp")


def materials(raws):
    parsed = [material(raw) for raw in raws]
    outbounds, tuples = [x[0] for x in parsed], [x[1] for x in parsed]
    require(len(parsed) == 3 and len(set(tuples)) == 3, "three_independently_faultable_peer_tuples_required")
    require(len({digest(encode(x)) for x in outbounds}) == 3, "three_distinct_materials_required")
    return outbounds, tuples


def feed_url(raw):
    require(0 < len(raw) <= 4096, "bounded_feed_url_required")
    value = raw.decode().removesuffix("\n")
    require(not any(c.isspace() or c == "\0" for c in value), "one_feed_url_required")
    url = urllib.parse.urlsplit(value)
    require(url.scheme == "https" and url.hostname and not url.username and
            not url.password and url.port in (None, 443) and not url.fragment,
            "ordinary_https_443_required")
    try:
        address = ipaddress.ip_address(url.hostname)
    except ValueError:
        require("." in url.hostname and not url.hostname.endswith((".local", ".localhost")), "public_feed_host_required")
    else:
        require(address.is_global, "public_feed_host_required")
    return value


def private_read(path, limit):
    """Linux operator inputs only. No symlink component, FIFO or unchecked reopen."""
    path = pathlib.Path(canonical_path(str(path)))
    for parent in (path, *path.parents):
        info = parent.lstat()
        require(not stat.S_ISLNK(info.st_mode), "symlink_input_refused")
        if parent != path:
            require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and
                    (stat.S_IMODE(info.st_mode) & 0o022 == 0 or info.st_mode & stat.S_ISVTX),
                    "trusted_input_ancestry_required")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as file:
        before = os.fstat(file.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and
                stat.S_IMODE(before.st_mode) & 0o077 == 0 and 0 < before.st_size <= limit,
                "bounded_root_private_file_required")
        raw = file.read(limit + 1)
        after, named = os.fstat(file.fileno()), path.lstat()
        stable = lambda x: (x.st_dev,x.st_ino,x.st_mode,x.st_uid,x.st_gid,x.st_size,x.st_mtime_ns,x.st_ctime_ns)
        require(stable(before) == stable(after) == stable(named) and
                stat.S_ISREG(named.st_mode) and len(raw) == before.st_size,
                "input_changed")
        return raw


def private_write(folder, name, raw):
    path = folder / name
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as file:
        os.fchmod(file.fileno(), 0o600)
        file.write(raw)
        file.flush()
        os.fsync(file.fileno())


def root_operator():
    require(os.name == "posix" and os.geteuid() == 0, "linux_root_offline_operator_required")


def prepare(manifest_path, output):
    root_operator()
    spec = decode(private_read(manifest_path, 64 << 10))
    required = {"schema", "run_id", "router_run", "router_binary", "profile_a", "profile_b", "profile_c", "feed_url_file", "catalog", "sources", "scope", "client_ipv4", "https_ipv4"}
    require(isinstance(spec, dict) and set(spec) == required and spec["schema"] == 1, "exact_manifest_required")
    run_id = spec["run_id"]
    require(isinstance(run_id, str) and re.fullmatch(r"[a-z0-9-]{12,64}", run_id), "finite_run_identity_required")
    remote = canonical_path(spec["router_run"])
    binary = canonical_path(spec["router_binary"])
    require(remote != "/" and not binary.startswith(remote + "/qa/"), "separate_router_paths_required")
    client = ipaddress.ip_address(spec["client_ipv4"])
    require(client.version == 4 and not client.is_loopback and not client.is_multicast and not client.is_unspecified, "selected_client_required")
    target = public4(spec["https_ipv4"])
    require(str(client) != target, "distinct_client_target_required")
    files, outbounds, tuples = {}, [], []
    input_paths = []
    for key, limit in (("profile_a", 256 << 10), ("profile_b", 256 << 10), ("profile_c", 256 << 10), ("feed_url_file", 4096), ("catalog", 4 << 20), ("sources", 4 << 20), ("scope", 64 << 10)):
        input_paths.append(canonical_path(spec[key]))
        files[key] = private_read(spec[key], limit)
    require(len(set(input_paths)) == len(input_paths), "distinct_input_paths_required")
    outbounds, tuples = materials([files[key] for key in ("profile_a", "profile_b", "profile_c")])
    feed_url(files["feed_url_file"])
    scope = decode(files["scope"])
    require(scope.get("schema") == 2 and scope.get("clients", {}).get("mode") == "selected_devices" and
            len(scope["clients"].get("device_ids", [])) == 1 and len(scope["clients"].get("segment_ids", [])) == 1 and
            scope["clients"].get("new_devices") == "base" and scope.get("traffic", {}).get("mode") == "selected_services" and
            not scope.get("rules") and not scope.get("exclusions") and not scope.get("russian", {}).get("enabled"),
            "one_selected_device_scope_required")
    package = pathlib.Path(canonical_path(str(output)))
    require(not package.exists() and not package.is_symlink(), "fresh_output_required")
    for parent in package.parents:
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode) and info.st_uid == 0 and
                (stat.S_IMODE(info.st_mode) & 0o022 == 0 or info.st_mode & stat.S_ISVTX), "trusted_output_ancestry_required")
    package.mkdir(mode=0o700)
    os.chmod(package, 0o700)
    for name in ("inputs", "feed"):
        (package / name).mkdir(mode=0o700)
    for key, raw in files.items():
        private_write(package / "inputs", key + (".txt" if key == "feed_url_file" else ".json"), raw)
    snapshots = {}
    for name, members in (("AB", outbounds[:2]), ("C", outbounds[2:])):
        raw = encode({"outbounds": members})
        filename = name + ".public.json"
        private_write(package / "feed", filename, raw)
        snapshots[name] = {"file": filename, "sha256": digest(raw), "bytes": len(raw), "content_type": "application/json"}
    private_write(package / "feed", "allowlist.json", encode({"schema": 1, "public_snapshots": snapshots}))
    for name, phase in (("control.json", "AB"), ("C.control.next.json", "C")):
        private_write(package / "feed", name, encode({"schema": 1, "phase": phase, "sha256": snapshots[phase]["sha256"]}))
    env = {PREFIX + "ENABLED": "1", PREFIX + "RUN_ID": run_id, PREFIX + "ROOT": remote + "/qa", PREFIX + "CLIENT_IPV4": str(client), PREFIX + "HTTPS_IPV4": target}
    for key in files:
        env[PREFIX + key.upper()] = remote + "/inputs/" + key + (".txt" if key == "feed_url_file" else ".json")
    private_write(package, "native.env.json", encode(env))
    argv = [binary, "-test.run=^TestXraySelectedAutoFetchNativeHTTP$", "-test.timeout=0", "-test.v", "-test.count=1"]
    private_write(package, "native.argv.json", encode(argv))
    shell = "#!/bin/sh\numask 077\nset +e\n" + "env " + " ".join(shlex.quote(k + "=" + v) for k, v in sorted(env.items())) + " " + " ".join(map(shlex.quote, argv)) + " >" + shlex.quote(remote + "/native.log") + " 2>&1\nrc=$?\nprintf '%s\\n' \"$rc\" >" + shlex.quote(remote + "/.actual-exit-next") + "\nmv " + shlex.quote(remote + "/.actual-exit-next") + " " + shlex.quote(remote + "/actual-exit") + "\nexit \"$rc\"\n"
    private_write(package, "native-run.sh", shell.encode())
    match = ["-p", "tcp", "-d", tuples[0][0] + "/32", "--dport", str(tuples[0][1]), "-m", "comment", "--comment", "rz-d10-" + run_id + "-A", "-j", "REJECT", "--reject-with", "tcp-reset"]
    fault = {"schema": 1, "run_id": run_id, "kind": "operator_plan_only_not_ownership", "precondition": "exclusive_QA_A_tuple_and_zero_exact_matching_rules", "insert": ["/opt/sbin/iptables", "-t", "filter", "-I", "OUTPUT", "1"] + match, "delete_after_same_original_successful_insert_ACK_only": ["/opt/sbin/iptables", "-t", "filter", "-D", "OUTPUT"] + match, "unknown_ACK": "refuse_automatic_delete_keep_artifacts_report_unknown", "flush_or_restore_whole_table": False}
    private_write(package, "fault-plan.private.json", encode(fault))
    private_write(package, "package.private.json", encode({"schema": 1, "run_id": run_id, "router_run": remote, "inputs": {k: digest(v) for k, v in files.items()}, "snapshots": snapshots, "native_evidence": False, "external_PC_and_actual_join_required": True}))
    return {"prepared": True, "native_started": False, "feed_published": False, "firewall_changed": False, "native_evidence": False}


def command_bytes(meta, status, verb):
    require(verb in (*PHASES, "ABORT"), "unknown_intent")
    require(status.get("run_id") == meta["run_id"], "actual_status_run_mismatch")
    phase = status.get("phase")
    require(verb == "ABORT" or phase == PHASES.get(verb), "actual_status_phase_mismatch")
    if verb == "FAULT_A":
        require(status.get("retained_a_rechecks", 0) >= 2, "two_original_a_rechecks_required")
    if verb == "STOP":
        require(status.get("retained_c_rechecks", 0) >= 2, "two_original_c_rechecks_required")
    if verb == "PUBLISHED_C":
        chrono = status.get("chronology", {})
        require(all(isinstance(chrono.get(key), str) and not chrono[key].startswith("0001-")
                    for key in ("FaultA", "FailureA1", "FailureA2", "FailureB", "Exhausted")),
                "native_exhaustion_fields_required")
    require(phase not in ("retired", "failed_retired", "cleanup_unconfirmed"), "terminal_or_cleanup_status_refused")
    return (verb + " " + meta["run_id"] + "\n").encode()


def command(package_path, status_path, verb):
    root_operator()
    package = pathlib.Path(canonical_path(str(package_path)))
    meta = decode(private_read(package / "package.private.json", 64 << 10))
    status = decode(private_read(status_path, 8192))
    raw = command_bytes(meta, status, verb)
    # An immutable intent file is deliberately NOT the native command target.
    # Root transfers it atomically only after its real fault/publication ACK.
    intent = package / (verb + ".intent")
    if intent.exists():
        require(private_read(intent,128) == raw, "existing_intent_changed")
    else:
        private_write(package, verb + ".intent", raw)
    return {"intent_prepared": True, "native_command_sent": False, "native_evidence": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="mode", required=True)
    prep = sub.add_parser("prepare"); prep.add_argument("--manifest", required=True); prep.add_argument("--out", required=True)
    emit = sub.add_parser("command"); emit.add_argument("--package", required=True); emit.add_argument("--status", required=True); emit.add_argument("--verb", choices=[*PHASES, "ABORT"], required=True)
    args = parser.parse_args()
    try:
        result = prepare(args.manifest, args.out) if args.mode == "prepare" else command(args.package, args.status, args.verb)
    except Refused as exc:
        print(json.dumps({"refused": str(exc), "native_evidence": False})); return 2
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        print(json.dumps({"refused": "private_input_or_output_unconfirmed", "native_evidence": False})); return 2
    print(json.dumps(result)); return 0


if __name__ == "__main__":
    sys.exit(main())
