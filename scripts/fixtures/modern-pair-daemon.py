#!/usr/bin/python3
"""Configured Ubuntu native fixture; not an Entware daemon implementation."""
import fcntl
import hashlib
import json
import os
import pathlib
import re
import resource
import stat
import sys


def refuse():
    raise SystemExit("modern pair daemon: fixed original invocation refused")


def protected(path, directory=False):
    info = os.lstat(path)
    if info.st_uid != 0 or info.st_mode & 0o077 or stat.S_ISLNK(info.st_mode):
        refuse()
    if directory != stat.S_ISDIR(info.st_mode):
        refuse()
    if not directory and (not stat.S_ISREG(info.st_mode) or info.st_size > 65536):
        refuse()
    return info


root = os.environ.get("TMPDIR", "")
if os.geteuid() != 0 or not re.fullmatch(r"/root/razvilka-modern-pair\.[A-Za-z0-9]+", root):
    refuse()
protected(root, True)
spec_path = root + "/modern-pair-native.json"
protected(spec_path)
spec = json.loads(pathlib.Path(spec_path).read_bytes())
if os.environ.get("RAZVILKA_MODERN_PAIR_NATIVE") != "1":
    refuse()
if hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest() != spec["launcher_sha256"]:
    refuse()
layout = os.environ.get("RAZVILKA_MODERN_PAIR_FD_LAYOUT")
if layout == "initial3":
    fd = 3
elif layout == "script4":
    fd = 4
    held = os.fstat(3)
    named = os.stat("/opt/bin/busybox")
    if (held.st_dev, held.st_ino) != (named.st_dev, named.st_ino):
        refuse()
    if hashlib.sha256(pathlib.Path("/opt/bin/busybox").read_bytes()).hexdigest() != spec["interpreter_sha256"]:
        refuse()
else:
    refuse()
if os.environ.get("RAZVILKA_RUNTIME_NATIVE_OUTER_NET_FD") != str(fd):
    refuse()
if fcntl.ioctl(fd, 0xb703) != 0x40000000:
    refuse()
held = os.fstat(fd)
current = os.stat("/proc/self/ns/net")
if (held.st_dev, held.st_ino) != (spec["namespace_device"], spec["namespace_inode"]):
    refuse()
if (held.st_dev, held.st_ino) == (current.st_dev, current.st_ino):
    refuse()

pid = "/opt/razvilka/run/razvilka.pid"
binary = "/opt/bin/razvilka"
stop = ["-K", "-p", pid, "-x", binary, "-s", "TERM"]
start = ["-S", "-b", "-m", "-p", pid, "-x", binary, "-O", "/opt/razvilka/log/server.log", "--"]
fixed_paths = [
    ("config", "/opt/etc/razvilka/config.json"),
    ("catalog", "/opt/etc/razvilka/service-catalog.json"),
    ("sources", "/opt/etc/razvilka/sources.json"),
    ("cache", "/opt/razvilka/cache"),
    ("stage", "/opt/razvilka/state/staging"),
    ("backups", "/opt/razvilka/state/backups"),
    ("token-file", "/opt/etc/razvilka/admin.token"),
    ("credentials-file", "/opt/etc/razvilka/admin.credentials.json"),
    ("custom-services", "/opt/etc/razvilka/custom-services.json"),
    ("node-state", "/opt/etc/razvilka/nodes-private"),
    ("devices", "/opt/etc/razvilka/devices.json"),
    ("cloudflare-state", "/opt/etc/razvilka/cloudflare-private"),
    ("community-catalog", "/opt/etc/razvilka/community-catalog.json"),
    ("warp-state", "/opt/razvilka/state/warp"),
    ("smart-route-state", "/opt/razvilka/state/smart-route.json"),
    ("dataplane-state", "/opt/razvilka/state/dataplane"),
    ("metrics-history", "/opt/razvilka/state/metrics/history.jsonl"),
    ("strategy-lab-state", "/opt/razvilka/state/strategy-lab.json"),
    ("audit-log", "/opt/razvilka/state/audit/events.jsonl"),
    ("dns-state", "/opt/razvilka/state/dns/state.json"),
    ("listen", "127.0.0.1:8787"),
]
for flag, path in fixed_paths:
    start += ["-" + flag, path]
job = os.environ.get("RAZVILKA_SELF_UPDATE_JOB", "")
helper = os.environ.get("RAZVILKA_SELF_UPDATE_HELPER_PID", "")
if job or helper:
    if layout != "script4" or not re.fullmatch(r"[0-9a-f]{32}", job) or not re.fullmatch(r"[1-9][0-9]*", helper) or int(helper) <= 1:
        refuse()
    start += ["-self-update-job", job, "-self-update-helper-pid", helper]
elif layout == "script4" and sys.argv[1:] != stop:
    refuse()
args = sys.argv[1:]
if args != stop and args != start:
    refuse()
if hashlib.sha256(pathlib.Path(binary).read_bytes()).hexdigest() not in (spec["source_sha256"], spec["candidate_sha256"]):
    refuse()
if hashlib.sha256(pathlib.Path('/usr/sbin/start-stop-daemon').read_bytes()).hexdigest() != spec["daemon_sha256"]:
    refuse()

# Single-thread Python launcher: close the entire inherited descriptor range.
# Only this child remaps4 ->3. The parent still owns its held interpreter3.
if fd == 4:
    os.dup2(4, 3, inheritable=True)
else:
    os.set_inheritable(3, True)
limit = resource.getrlimit(resource.RLIMIT_NOFILE)[1]
if limit == resource.RLIM_INFINITY or limit > 1048576:
    refuse()
os.closerange(4, limit)
os.environ["RAZVILKA_RUNTIME_NATIVE_OUTER_NET_FD"] = "3"
os.environ.pop("RAZVILKA_MODERN_PAIR_FD_LAYOUT", None)
if layout != "initial3":
    os.environ.pop("SSL_CERT_FILE", None)
    os.environ.pop("SSL_CERT_DIR", None)
if args == start:
    args = ["--no-close"] + args
os.execv("/usr/sbin/start-stop-daemon", ["/usr/sbin/start-stop-daemon"] + args)
