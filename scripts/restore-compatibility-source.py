#!/usr/bin/env python3
"""Restore an allowlisted historical SOURCE fixture; never attach old history.

No source is executed. A requested Git fixture contains one original commit,
its verified tree/blobs and a shallow boundary, with no remote or parent objects.
Failed destinations are retained for inspection and are never overwritten.
"""
import argparse
import base64
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
import threading

PINS = Path(__file__).resolve().parent / "fixtures/compatibility-sources/sources.json"
REPOSITORY = "ArtixSx/RAZVILKA"
RELEASE = "compatibility-sources-20261116"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def git_oid(kind, data):
    return hashlib.sha1(kind.encode() + b" " + str(len(data)).encode() + b"\0" + data).hexdigest()


def git_env():
    env = {k: v for k, v in os.environ.items() if not k.upper().startswith("GIT_")}
    env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
               GIT_TERMINAL_PROMPT="0", GIT_OPTIONAL_LOCKS="0", GIT_NO_LAZY_FETCH="1")
    return env


def git(cwd, *args, data=None, stdout=subprocess.PIPE):
    result = subprocess.run(git_command(cwd, *args), cwd=cwd,
                            input=data, stdout=stdout, stderr=subprocess.PIPE,
                            env=git_env(), timeout=120)
    require(result.returncode == 0, "Git source/fixture verification failed (Git must support --no-lazy-fetch)")
    return result.stdout


def git_command(cwd, *args):
    # A sudo fixture may read the runner-owned checkout. Trust only this exact
    # explicitly selected directory for this invocation, never '*' or config
    # persisted in the user's/current repository.
    canonical = str(Path(cwd).resolve(strict=True))
    return ["git", "--no-lazy-fetch", "-c", "core.fsmonitor=false", "-c", "safe.directory=" + canonical, *args]


def pins(commit):
    require(re.fullmatch(r"[0-9a-f]{40}", commit), "exact allowlisted commit required")
    document = json.loads(PINS.read_text(encoding="utf-8"))
    require(document["schema"] == 1 and document["repository"] == REPOSITORY
            and document["release_tag"] == RELEASE, "unsupported source pins")
    matches = [row for row in document["sources"] if row["commit"] == commit]
    require(len(matches) == 1, "commit is not allowlisted")
    row = matches[0]
    raw = base64.b64decode(row["commit_object_base64"], validate=True)
    require(git_oid("commit", raw) == commit and raw.startswith(("tree " + row["tree"] + "\n").encode()),
            "original commit object identity mismatch")
    require(row["archive"] == "RAZVILKA-" + commit + ".tar.gz", "invalid archive name")
    return row


def copy_exact(source, target, size, digest):
    checksum = hashlib.sha256()
    remaining = size
    while remaining:
        chunk = source.read(min(1 << 20, remaining))
        require(chunk, "source is shorter than pinned size")
        target.write(chunk)
        checksum.update(chunk)
        remaining -= len(chunk)
    require(not source.read(1), "source exceeds pinned size")
    require(checksum.hexdigest() == digest, "source SHA256 mismatch")
    target.flush()
    target.seek(0)


def obtain_tar(row, raw, archive_dir=None, local_repo=None):
    # Only an absent exact commit may choose the archive fallback. Corruption,
    # a changed object/tree or a different git-archive format is a hard refusal.
    if local_repo is not None:
        repo = Path(local_repo).absolute()
        git(repo, "rev-parse", "--git-dir")
        state = git(repo, "cat-file", "--batch-check=%(objectname) %(objecttype)",
                    data=(row["commit"] + "\n").encode()).decode().strip()
        if state != row["commit"] + " missing":
            require(state == row["commit"] + " commit", "local object is not the exact commit")
            actual = git(repo, "cat-file", "commit", row["commit"])
            require(actual == base64.b64decode(row["commit_object_base64"]), "local commit bytes changed")
            require(git(repo, "rev-parse", row["commit"] + "^{tree}").decode().strip() == row["tree"],
                    "local tree identity mismatch")
            command = git_command(repo, "archive", "--format=tar",
                                  "--prefix=RAZVILKA-" + row["commit"] + "/", row["commit"])
            with subprocess.Popen(command, cwd=repo, env=git_env(), stdout=subprocess.PIPE,
                                  stderr=subprocess.DEVNULL) as process:
                timer = threading.Timer(120, process.kill)
                timer.daemon = True
                timer.start()
                try:
                    copy_exact(process.stdout, raw, row["uncompressed_archive_size"], row["uncompressed_archive_sha256"])
                    require(process.wait(timeout=10) == 0, "local archive command failed")
                finally:
                    timer.cancel()
                    if process.poll() is None:
                        process.kill()
                    process.wait()
                    timer.join()
            return "local-git"
    # Copy once into an owned anonymous file. Validation/extraction never reopen
    # the caller's archive pathname, so replacement after validation is inert.
    if archive_dir is None:
        archive_dir = os.environ.get("RAZVILKA_COMPAT_ARCHIVE_DIR")
    require(archive_dir, "Historical source is unavailable locally. Provide the verified private archives "
                         "with --archive-dir or RAZVILKA_COMPAT_ARCHIVE_DIR.")
    with tempfile.TemporaryFile() as compressed:
        path = Path(archive_dir) / row["archive"]
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and not getattr(info, "st_file_attributes", 0) & 0x400,
                "archive must be a regular file")
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0)
                     | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        source = os.fdopen(fd, "rb")
        if not os.path.samestat(info, os.fstat(source.fileno())):
            source.close()
            raise ValueError("archive changed while opening")
        with source:
            copy_exact(source, compressed, row["size"], row["sha256"])
        with gzip.GzipFile(fileobj=compressed) as uncompressed:
            copy_exact(uncompressed, raw, row["uncompressed_archive_size"], row["uncompressed_archive_sha256"])
    return "local-archive"


def safe_relative(name):
    require(isinstance(name, str) and name and len(name.encode("utf-8")) <= 4096,
            "invalid source path length")
    require(not any(c in name for c in '\\:<>"|?*') and not any(ord(c) < 32 for c in name)
            and not name.startswith("/"), "unsafe source path")
    parts = name.split("/")
    for part in parts:
        require(part not in ("", ".", "..") and part.casefold() != ".git"
                and part.rstrip(" .") == part, "unsafe source component")
        require(not re.fullmatch(r"(?i)(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?", part),
                "nonportable reserved source component")
    require(str(PurePosixPath(name)) == name, "noncanonical source path")
    return parts


def tree_identity(files):
    root = {}
    for name, item in files.items():
        node = root
        parts = safe_relative(name)
        for part in parts[:-1]:
            node = node.setdefault(part, {})
            require(isinstance(node, dict), "source file/directory overlap")
        require(parts[-1] not in node, "duplicate source path")
        node[parts[-1]] = (item["mode"], item["blob"])

    def encode(node):
        entries = []
        for name, child in node.items():
            directory = isinstance(child, dict)
            mode, oid = ("40000", encode(child)) if directory else child
            key = name.encode("utf-8") + (b"/" if directory else b"")
            entries.append((key, mode.encode() + b" " + name.encode("utf-8") + b"\0" + bytes.fromhex(oid)))
        return git_oid("tree", b"".join(payload for _, payload in sorted(entries)))
    return encode(root)


def validate_tar(raw, row):
    raw.seek(0)
    files, paths, kinds = {}, {}, {}
    prefix = "RAZVILKA-" + row["commit"]
    total = count = 0
    archive = tarfile.open(fileobj=raw, mode="r:")
    try:
        for member in archive:
            count += 1
            require(count <= row["member_count"], "too many archive entries")
            require(member.type in (tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE)
                    and not any(k.startswith("GNU.sparse") for k in member.pax_headers),
                    "archive links and special files are forbidden")
            require(member.mode in (0o644, 0o664, 0o755, 0o775), "unsafe archive mode")
            if member.name == prefix:
                require(member.isdir() and "" not in kinds, "invalid archive root")
                kinds[""] = "dir"
                continue
            require(member.name.startswith(prefix + "/"), "archive prefix mismatch")
            name = member.name[len(prefix) + 1:]
            safe_relative(name)
            require(name.casefold() not in paths, "duplicate/case-alias archive path")
            paths[name.casefold()] = name
            kinds[name] = "dir" if member.isdir() else "file"
            if member.isdir():
                require(member.size == 0, "directory contains data")
                continue
            require(0 <= member.size <= row["max_file_bytes"], "source file exceeds pinned bound")
            total += member.size
            require(total <= row["content_bytes"], "source payload exceeds pinned bound")
            with archive.extractfile(member) as stream:
                data = stream.read(member.size + 1)
            require(len(data) == member.size, "source payload length mismatch")
            files[name] = {"member": member, "size": len(data), "sha256": hashlib.sha256(data).hexdigest(),
                           "blob": git_oid("blob", data), "mode": "100755" if member.mode & 0o111 else "100644"}
        require(count == row["member_count"] and len(files) == row["file_count"]
                and total == row["content_bytes"], "source inventory mismatch")
        for name in kinds:
            for parent in PurePosixPath(name).parents:
                if str(parent) != ".":
                    require(kinds.get(str(parent)) == "dir", "missing or non-directory source parent")
        require(all(name in files for name in row["license_notice_paths"]), "missing original license notice")
        require(tree_identity(files) == row["tree"], "source Git tree identity mismatch")
        return archive, files
    except BaseException:
        archive.close()
        raise


def reject_link(info):
    require(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode)
            and not getattr(info, "st_file_attributes", 0) & 0x400, "symlink/reparse destination directory")


class SafeDestination:
    """New tree only, anchored directories; never remove a caller's directory."""
    def __init__(self, path):
        self.path = Path(path)
        require(self.path.is_absolute() and self.path.name and str(self.path) == os.path.abspath(self.path),
                "absolute canonical new destination required")
        self.fds = {}
        self.handles = []
        self.parents = []

    def pin_windows(self, path):
        import ctypes
        from ctypes import wintypes
        api = ctypes.WinDLL("kernel32", use_last_error=True)
        api.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                                   wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
        api.CreateFileW.restype = wintypes.HANDLE
        api.CloseHandle.argtypes = [wintypes.HANDLE]
        # No FILE_SHARE_DELETE: an ancestor cannot become a junction/rename
        # during extraction or the optional Git fixture initialization.
        handle = api.CreateFileW(str(path), 0x80, 3, None, 3, 0x02200000, None)
        require(handle != ctypes.c_void_p(-1).value, "cannot pin destination directory")
        self.handles.append((api, handle))
        reject_link(path.lstat())

    def __enter__(self):
        try:
            chain = list(reversed(self.path.parent.parents)) + [self.path.parent]
            if os.name == "nt":
                for parent in chain:
                    self.pin_windows(parent)
                self.path.mkdir(mode=0o700, exist_ok=False)
                self.pin_windows(self.path)
            else:
                fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                self.parents.append(fd)
                for part in self.path.parent.parts[1:]:
                    fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                    self.parents.append(fd)
                os.mkdir(self.path.name, mode=0o700, dir_fd=fd)
                self.fds[""] = os.open(self.path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def directory(self, name):
        if not name or name == ".":
            return self.fds.get("")
        if name in self.fds:
            return self.fds[name]
        parts = safe_relative(name)
        parent = self.directory("/".join(parts[:-1]))
        if os.name == "nt":
            target = self.path.joinpath(*parts)
            target.mkdir(mode=0o755, exist_ok=False)
            self.pin_windows(target)
            self.fds[name] = None
        else:
            os.mkdir(parts[-1], mode=0o755, dir_fd=parent)
            self.fds[name] = os.open(parts[-1], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        return self.fds[name]

    def write(self, name, data, mode):
        parts = safe_relative(name)
        parent = self.directory("/".join(parts[:-1]))
        if os.name == "nt":
            fd = os.open(self.path.joinpath(*parts), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_BINARY, mode)
        else:
            fd = os.open(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode, dir_fd=parent)
            os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)

    def verify(self, name, item):
        parts = safe_relative(name)
        if os.name == "nt":
            path = self.path.joinpath(*parts)
            require(not path.is_symlink() and not getattr(path.lstat(), "st_file_attributes", 0) & 0x400,
                    "restored file became a link")
            fd = os.open(path, os.O_RDONLY | os.O_BINARY)
        else:
            fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=self.fds["/".join(parts[:-1])])
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            require(stat.S_ISREG(info.st_mode) and info.st_size == item["size"], "restored file identity mismatch")
            require(hashlib.file_digest(stream, "sha256").hexdigest() == item["sha256"], "restored file SHA256 mismatch")
            if os.name != "nt":
                require(stat.S_IMODE(info.st_mode) == (0o755 if item["mode"] == "100755" else 0o644), "restored file mode mismatch")

    def git_cwd(self):
        if os.name != "nt":
            # /proc is available on supported Linux CI. The parent descriptor
            # anchors cwd even if an uncooperative actor renames an ancestor.
            return f"/proc/{os.getpid()}/fd/{self.fds['']}"
        return str(self.path)

    def named_current(self):
        info = self.path.lstat()
        reject_link(info)
        if os.name != "nt":
            require(os.path.samestat(info, os.fstat(self.fds[""])), "destination name moved during restoration")

    def __exit__(self, *unused):
        for fd in reversed(list(self.fds.values()) + self.parents):
            if fd is not None:
                os.close(fd)
        for api, handle in reversed(self.handles):
            api.CloseHandle(handle)
        self.fds.clear()
        self.parents.clear()
        self.handles.clear()


def git_fixture(destination, files, row):
    cwd = destination.git_cwd()
    with tempfile.TemporaryDirectory() as template:
        git(cwd, "init", "--quiet", "--template=" + template)
    git(cwd, "config", "core.autocrlf", "false")
    git(cwd, "config", "core.filemode", "false" if os.name == "nt" else "true")
    if os.name == "nt":
        git(cwd, "config", "core.longpaths", "true")
    names = sorted(files)
    hashes = git(cwd, "hash-object", "-w", "--no-filters", "--stdin-paths",
                 data=("\n".join(names) + "\n").encode()).decode().splitlines()
    require(hashes == [files[name]["blob"] for name in names], "isolated Git blob identity mismatch")
    index = b"".join((files[name]["mode"] + " " + files[name]["blob"] + "\t" + name).encode() + b"\0" for name in names)
    git(cwd, "update-index", "-z", "--index-info", data=index)
    require(git(cwd, "write-tree").decode().strip() == row["tree"], "isolated Git tree mismatch")
    commit = git(cwd, "hash-object", "-t", "commit", "-w", "--stdin",
                 data=base64.b64decode(row["commit_object_base64"])).decode().strip()
    require(commit == row["commit"], "isolated original commit mismatch")
    # Git is initialized only in this newly created fixture. No origin, old
    # parents, source worktree registration or current-repository ref is used.
    gitdir = Path(cwd) / ".git"
    head_line = (commit + "\n").encode("ascii")
    (gitdir / "shallow").write_bytes(head_line)
    (gitdir / "HEAD").write_bytes(head_line)
    require(git(cwd, "rev-parse", "HEAD").decode().strip() == commit, "isolated HEAD mismatch")
    require(git(cwd, "rev-list", "--count", "HEAD").strip() == b"1", "fixture has historical ancestry")
    require(not git(cwd, "remote").strip(), "fixture has a remote")
    git(cwd, "diff", "--exit-code", "--no-ext-diff", "--no-textconv", "HEAD", "--")
    git(cwd, "fsck", "--no-reflogs", "--connectivity-only")


def restore(commit, destination, archive_dir=None, local_repo=None, make_git=False):
    row = pins(commit)
    require(not os.path.lexists(destination), "destination already exists; nothing overwritten")
    with tempfile.TemporaryFile() as raw:
        origin = obtain_tar(row, raw, archive_dir, local_repo)
        archive, files = validate_tar(raw, row)
        with archive, SafeDestination(destination) as target:
            for name, item in files.items():
                with archive.extractfile(item["member"]) as stream:
                    data = stream.read(item["size"] + 1)
                require(len(data) == item["size"] and hashlib.sha256(data).hexdigest() == item["sha256"],
                        "validated archive changed before extraction")
                target.write(name, data, 0o755 if item["mode"] == "100755" else 0o644)
            for name, item in files.items():
                target.verify(name, item)
            if make_git:
                git_fixture(target, files, row)
                for name, item in files.items():
                    target.verify(name, item)
            target.named_current()
    return {"commit": commit, "tree": row["tree"], "source": origin, "files": len(files),
            "tar_sha256": row["uncompressed_archive_sha256"], "byte_readback": "PASS",
            "git_modes": "PASS", "filesystem_modes": "not representable on Windows" if os.name == "nt" else "PASS",
            "git_fixture": bool(make_git), "history_attached_to_current_repo": False, "destination": str(destination)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--destination", required=True)
    parser.add_argument("--archive-dir", help="Directory of pinned private archives (default: RAZVILKA_COMPAT_ARCHIVE_DIR)")
    parser.add_argument("--local-repo")
    parser.add_argument("--git-fixture", action="store_true")
    args = parser.parse_args()
    try:
        print(json.dumps(restore(args.commit, args.destination, args.archive_dir, args.local_repo, args.git_fixture), indent=2))
    except (OSError, ValueError, KeyError, tarfile.TarError, subprocess.SubprocessError) as error:
        print("Compatibility source refused; any new destination is retained for inspection: " + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
