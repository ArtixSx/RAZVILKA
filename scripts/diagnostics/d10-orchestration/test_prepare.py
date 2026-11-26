"""Offline data/intent tests; no network, process, tunnel or firewall actions."""
import copy
import json
import os
import pathlib
import stat
import tempfile
import unittest
import prepare as qa


def profile(ip, suffix):
    return qa.encode({"outbounds": [{"type": "vless", "server": ip, "server_port": 443,
                                   "uuid": "00000000-0000-4000-8000-00000000000" + suffix,
                                   "tls": {"enabled": True, "server_name": "test.example"}}]})


class Contracts(unittest.TestCase):
    def test_exact_materials_independent_numeric_tuples(self):
        raws = [profile("1.1.1.1", "1"), profile("8.8.8.8", "2"), profile("9.9.9.9", "3")]
        out, peers = qa.materials(raws)
        self.assertEqual(len(set(peers)), 3)
        self.assertEqual(len(out), 3)
        with self.assertRaises(qa.Refused):
            qa.materials([raws[0], profile("1.1.1.1", "2"), raws[2]])
        for update in ({"server": "127.0.0.1"}, {"server": "host.example"}, {"network": "udp"},
                       {"transport": {"type": "ws"}}, {"server_port": 0}, {"tls": {"enabled": True, "insecure": True}}):
            doc = qa.decode(raws[0]); doc["outbounds"][0].update(update)
            with self.assertRaises((qa.Refused, ValueError)):
                qa.material(qa.encode(doc))

    def test_url_and_duplicate_json_are_not_relaxed(self):
        self.assertEqual(qa.feed_url(b"https://feed.example/opaque\n"), "https://feed.example/opaque")
        for raw in (b"http://feed.example/", b"https://127.0.0.1/", b"https://feed.example:8443/",
                    b"https://secret@feed.example/", b"https://feed.example/\nextra", b"https://feed.example/#x"):
            with self.assertRaises((qa.Refused, ValueError)):
                qa.feed_url(raw)
        with self.assertRaises(qa.Refused):
            qa.decode(b'{"secret":"a","secret":"b"}')

    def test_commands_require_exact_run_phase_and_rechecks(self):
        meta = {"run_id": "root-auto-0123456789"}
        phases = {"FAULT_A": "applied_a", "PUBLISHED_C": "exhausted_ab", "STOP": "committed_c"}
        for verb, phase in phases.items():
            status = {"run_id": meta["run_id"], "phase": phase, "retained_a_rechecks": 2, "retained_c_rechecks": 2,
                      "chronology": {k: "2026-10-16T00:00:00Z" for k in ("FaultA", "FailureA1", "FailureA2", "FailureB", "Exhausted")}}
            self.assertEqual(qa.command_bytes(meta, status, verb), (verb + " " + meta["run_id"] + "\n").encode())
            for change in ({"run_id": "other"}, {"phase": "initializing"}, {"phase": "retired"}):
                bad = copy.deepcopy(status); bad.update(change)
                with self.assertRaises(qa.Refused):
                    qa.command_bytes(meta, bad, verb)
        with self.assertRaises(qa.Refused):
            qa.command_bytes(meta, {"run_id": meta["run_id"], "phase": "applied_a", "retained_a_rechecks": 1}, "FAULT_A")
        with self.assertRaises(qa.Refused):
            qa.command_bytes(meta, {"run_id": meta["run_id"], "phase": "exhausted_ab"}, "PUBLISHED_C")

    @unittest.skipUnless(os.name == "posix" and os.geteuid() == 0, "actual Linux root private-file contract")
    def test_private_package_no_execution_and_exact_own_fault_plan(self):
        with tempfile.TemporaryDirectory() as folder:
            base = pathlib.Path(folder)
            spec = {"schema": 1, "run_id": "root-auto-0123456789", "router_run": "/opt/var/qa/auto-fixture",
                    "router_binary": "/opt/var/qa/native.test", "client_ipv4": "192.168.1.40", "https_ipv4": "1.1.1.1"}
            values = {"profile_a": profile("1.1.1.1", "1"), "profile_b": profile("8.8.8.8", "2"),
                      "profile_c": profile("9.9.9.9", "3"), "feed_url_file": b"https://feed.example/opaque\n",
                      "catalog": b"{}", "sources": b"{}", "scope": qa.encode({"schema": 2, "clients": {"mode": "selected_devices", "device_ids": ["known"], "segment_ids": ["home"], "new_devices": "base"}, "traffic": {"mode": "selected_services"}})}
            for key, raw in values.items():
                path = base / key; path.write_bytes(raw); path.chmod(0o600); spec[key] = str(path)
            manifest = base / "manifest.json"; manifest.write_bytes(qa.encode(spec)); manifest.chmod(0o600)
            package = base / "package"
            self.assertFalse(qa.prepare(manifest, package)["native_started"])
            for path in [package, *package.rglob("*")]:
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700 if path.is_dir() else 0o600)
            env = qa.decode((package / "native.env.json").read_bytes())
            self.assertEqual(env[qa.PREFIX + "ROOT"], spec["router_run"] + "/qa")
            self.assertNotIn("tls", env)
            fault = qa.decode((package / "fault-plan.private.json").read_bytes())
            self.assertEqual(fault["insert"][:6], ["/opt/sbin/iptables", "-t", "filter", "-I", "OUTPUT", "1"])
            self.assertNotIn("-F", fault["insert"])
            self.assertIn("1.1.1.1/32", fault["insert"])
            self.assertNotIn("8.8.8.8/32", fault["insert"])
            self.assertFalse(fault["flush_or_restore_whole_table"])
            with self.assertRaises(qa.Refused):
                qa.prepare(manifest, package)
            alias = base / "alias"; alias.symlink_to(manifest)
            with self.assertRaises(qa.Refused):
                qa.private_read(alias, 65536)
            fifo = base / "fifo"; os.mkfifo(fifo, 0o600)
            with self.assertRaises(qa.Refused):
                qa.private_read(fifo, 65536)


if __name__ == "__main__":
    unittest.main()
