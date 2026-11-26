#!/usr/bin/env python3
"""Portable safety/identity tests. No network and no historical ref fetch."""
import base64
import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location("compat_restore", Path(__file__).with_name("restore-compatibility-source.py"))
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def fixture(folder, files=None):
    files = files or {"LICENSE": b"original license\n", "foo.c": b"file\n", "foo/bar": b"#!/bin/sh\n",
                      "\u0434\u0430\u043d\u043d\u044b\u0435.txt": b"unicode filename\n"}
    entries = {n: {"blob": MODULE.git_oid("blob", b), "mode": "100755" if n == "foo/bar" else "100644"}
               for n, b in files.items()}
    tree = MODULE.tree_identity(entries)
    commit_raw = (f"tree {tree}\nparent {'1' * 40}\nauthor Fixture <fixture@example.invalid> 1 +0000\n"
                  "committer Fixture <fixture@example.invalid> 1 +0000\n\nOriginal fixture commit\n").encode()
    commit = MODULE.git_oid("commit", commit_raw)
    prefix = "RAZVILKA-" + commit
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w", format=tarfile.PAX_FORMAT) as archive:
        directories = {prefix}
        for name in files:
            parts = name.split("/")
            directories.update(prefix + "/" + "/".join(parts[:i]) for i in range(1, len(parts)))
        for name in sorted(directories):
            item = tarfile.TarInfo(name)
            item.type, item.mode = tarfile.DIRTYPE, 0o775
            archive.addfile(item)
        for name, data in files.items():
            item = tarfile.TarInfo(prefix + "/" + name)
            item.mode = 0o775 if entries[name]["mode"] == "100755" else 0o664
            item.size = len(data)
            archive.addfile(item, io.BytesIO(data))
    raw = stream.getvalue()
    compressed = gzip.compress(raw, mtime=0)
    row = {"commit": commit, "tree": tree, "archive": prefix + ".tar.gz", "size": len(compressed),
           "sha256": hashlib.sha256(compressed).hexdigest(), "uncompressed_archive_size": len(raw),
           "uncompressed_archive_sha256": hashlib.sha256(raw).hexdigest(), "file_count": len(files),
           "member_count": len(files) + len(directories), "content_bytes": sum(map(len, files.values())),
           "max_file_bytes": max(map(len, files.values())), "license_notice_paths": ["LICENSE"],
           "commit_object_base64": base64.b64encode(commit_raw).decode()}
    folder.joinpath(row["archive"]).write_bytes(compressed)
    metadata = folder / "pins.json"
    metadata.write_text(json.dumps({"schema": 1, "repository": MODULE.REPOSITORY,
                                   "release_tag": MODULE.RELEASE, "sources": [row]}), encoding="utf-8")
    return row, metadata, raw


class RestoreTests(unittest.TestCase):
    def test_private_archive_directory_and_explicit_override(self):
        with tempfile.TemporaryDirectory() as base:
            folder = Path(base)
            row, metadata, _ = fixture(folder)
            with mock.patch.object(MODULE, "PINS", metadata):
                with mock.patch.dict(os.environ, {"RAZVILKA_COMPAT_ARCHIVE_DIR": str(folder)}):
                    result = MODULE.restore(row["commit"], folder / "from-env")
                    self.assertEqual(result["source"], "local-archive")
                with mock.patch.dict(os.environ, {"RAZVILKA_COMPAT_ARCHIVE_DIR": str(folder / "missing")}):
                    result = MODULE.restore(row["commit"], folder / "explicit", archive_dir=folder)
                    self.assertEqual(result["source"], "local-archive")
                with mock.patch.dict(os.environ, {"RAZVILKA_COMPAT_ARCHIVE_DIR": ""}):
                    refused = folder / "unavailable"
                    with self.assertRaisesRegex(ValueError, "RAZVILKA_COMPAT_ARCHIVE_DIR"):
                        MODULE.restore(row["commit"], refused)
                    self.assertFalse(refused.exists())

    def test_archive_original_commit_tree_unicode_and_modes(self):
        with tempfile.TemporaryDirectory() as base:
            folder = Path(base)
            row, metadata, _ = fixture(folder)
            with mock.patch.object(MODULE, "PINS", metadata):
                result = MODULE.restore(row["commit"], folder / "restored", archive_dir=folder, make_git=True)
            self.assertEqual(result["tree"], row["tree"])
            self.assertEqual(result["source"], "local-archive")
            self.assertTrue((folder / "restored/LICENSE").is_file())
            self.assertEqual(MODULE.git(folder / "restored", "rev-list", "--count", "HEAD").strip(), b"1")
            self.assertEqual(MODULE.git(folder / "restored", "rev-parse", "HEAD").decode().strip(), row["commit"])
            self.assertEqual(MODULE.git(folder / "restored", "cat-file", "commit", "HEAD"), base64.b64decode(row["commit_object_base64"]))

    def test_unsafe_paths_and_git_metadata_refused(self):
        for path in ("../escape", "/absolute", "a/../b", "a//b", "a/./b", "a\\b", "C:stream",
                     ".git/config", "a/.GIT/config", "CON", "a/nul.txt", "a. ", "a\nb", "a\tb"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                MODULE.safe_relative(path)

    def test_archive_special_duplicate_alias_and_mode_refusals(self):
        with tempfile.TemporaryDirectory() as base:
            row, _, raw = fixture(Path(base))
            for mode in ("symlink", "hardlink", "device", "fifo", "duplicate", "case-alias", "dotgit", "setuid"):
                with self.subTest(mode=mode):
                    mutated = io.BytesIO()
                    with tarfile.open(fileobj=io.BytesIO(raw)) as source, tarfile.open(fileobj=mutated, mode="w") as target:
                        for member in source:
                            target.addfile(member, source.extractfile(member) if member.isfile() else None)
                        extra = tarfile.TarInfo("RAZVILKA-" + row["commit"] + "/extra")
                        extra.mode = 0o644
                        if mode in ("symlink", "hardlink", "device", "fifo"):
                            extra.type = {"symlink": tarfile.SYMTYPE, "hardlink": tarfile.LNKTYPE,
                                          "device": tarfile.CHRTYPE, "fifo": tarfile.FIFOTYPE}[mode]
                            extra.linkname = "../outside"
                        elif mode == "duplicate":
                            extra.name = "RAZVILKA-" + row["commit"] + "/LICENSE"
                        elif mode == "case-alias":
                            extra.name = "RAZVILKA-" + row["commit"] + "/license"
                        elif mode == "dotgit":
                            extra.name = "RAZVILKA-" + row["commit"] + "/.git/config"
                        elif mode == "setuid":
                            extra.mode = 0o4755
                        target.addfile(extra)
                    changed = dict(row, member_count=row["member_count"] + 1)
                    with self.assertRaises(ValueError):
                        MODULE.validate_tar(io.BytesIO(mutated.getvalue()), changed)

    def test_hash_wrong_commit_existing_destination_fail_before_write(self):
        with tempfile.TemporaryDirectory() as base:
            folder = Path(base)
            row, metadata, _ = fixture(folder)
            destination = folder / "restored"
            with mock.patch.object(MODULE, "PINS", metadata):
                with self.assertRaises(ValueError):
                    MODULE.restore("0" * 40, destination, archive_dir=folder)
                (folder / row["archive"]).write_bytes(b"corrupted")
                with self.assertRaises(ValueError):
                    MODULE.restore(row["commit"], destination, archive_dir=folder)
                self.assertFalse(destination.exists())
                destination.mkdir()
                sentinel = destination / "keep"
                sentinel.write_bytes(b"unchanged")
                with self.assertRaises(ValueError):
                    MODULE.restore(row["commit"], destination, archive_dir=folder)
                self.assertEqual(sentinel.read_bytes(), b"unchanged")

    def test_archive_path_replacement_cannot_change_validated_snapshot(self):
        with tempfile.TemporaryDirectory() as base, tempfile.TemporaryFile() as copied:
            folder = Path(base)
            row, _, _ = fixture(folder)
            MODULE.obtain_tar(row, copied, archive_dir=folder)
            (folder / row["archive"]).write_bytes(b"changed after validation")
            archive, files = MODULE.validate_tar(copied, row)
            archive.close()
            self.assertEqual(MODULE.tree_identity(files), row["tree"])

    def test_commit_object_forgery_refused(self):
        with tempfile.TemporaryDirectory() as base:
            row, metadata, _ = fixture(Path(base))
            value = json.loads(metadata.read_text())
            value["sources"][0]["commit_object_base64"] = base64.b64encode(b"different commit").decode()
            metadata.write_text(json.dumps(value))
            with mock.patch.object(MODULE, "PINS", metadata), self.assertRaises(ValueError):
                MODULE.pins(row["commit"])

    def test_symlink_parent_refused(self):
        with tempfile.TemporaryDirectory() as base:
            folder = Path(base)
            (folder / "outside").mkdir()
            try:
                os.symlink(folder / "outside", folder / "link", target_is_directory=True)
            except OSError:
                self.skipTest("OS does not permit test symlink creation; Linux CI must run this case")
            with self.assertRaises((OSError, ValueError)):
                with MODULE.SafeDestination(folder / "link/new"):
                    self.fail("symlink parent admitted")
            self.assertFalse((folder / "outside/new").exists())

    def test_parent_rename_does_not_redirect_writes(self):
        with tempfile.TemporaryDirectory() as base:
            folder = Path(base)
            parent = folder / "parent"
            parent.mkdir()
            with MODULE.SafeDestination(parent / "new") as target:
                if os.name == "nt":
                    with self.assertRaises(OSError):
                        parent.rename(folder / "moved")
                else:
                    parent.rename(folder / "moved")
                    parent.mkdir()
                target.write("proof", b"owned only", 0o644)
                if os.name != "nt":
                    self.assertFalse((parent / "new/proof").exists())
                    self.assertEqual((folder / "moved/new/proof").read_bytes(), b"owned only")
                    with self.assertRaises((OSError, ValueError)):
                        target.named_current()
                else:
                    target.named_current()

    def test_local_present_commit_archive_mismatch_never_falls_back(self):
        with tempfile.TemporaryDirectory() as base:
            folder = Path(base)
            row, metadata, _ = fixture(folder)
            with mock.patch.object(MODULE, "PINS", metadata):
                MODULE.restore(row["commit"], folder / "local", archive_dir=folder, make_git=True)
                # The synthetic tar is deliberately not git archive's encoding.
                # Valid archive fallback must not mask this local hash failure.
                with self.assertRaises(ValueError):
                    MODULE.restore(row["commit"], folder / "must-not-exist", archive_dir=folder,
                                   local_repo=folder / "local")
                self.assertFalse((folder / "must-not-exist").exists())

    def test_absent_local_commit_uses_only_pinned_archive(self):
        with tempfile.TemporaryDirectory() as base:
            folder = Path(base)
            row, metadata, _ = fixture(folder)
            (folder / "empty").mkdir()
            MODULE.git(folder / "empty", "init", "--quiet", "--template=" + str(folder / "empty"))
            with mock.patch.object(MODULE, "PINS", metadata):
                result = MODULE.restore(row["commit"], folder / "restored", archive_dir=folder,
                                        local_repo=folder / "empty")
            self.assertEqual(result["source"], "local-archive")

    def test_missing_promisor_blob_never_fetches_or_mutates_source(self):
        with tempfile.TemporaryDirectory() as base:
            folder = Path(base)
            row, metadata, _ = fixture(folder)
            source, remote = folder / "source", folder / "local-promisor"
            with mock.patch.object(MODULE, "PINS", metadata):
                MODULE.restore(row["commit"], source, archive_dir=folder, make_git=True)
                MODULE.restore(row["commit"], remote, archive_dir=folder, make_git=True)
                raw = MODULE.git(source, "archive", "--format=tar",
                                 "--prefix=RAZVILKA-" + row["commit"] + "/", row["commit"])
                value = json.loads(metadata.read_text())
                value["sources"][0]["uncompressed_archive_size"] = len(raw)
                value["sources"][0]["uncompressed_archive_sha256"] = hashlib.sha256(raw).hexdigest()
                metadata.write_text(json.dumps(value))
                MODULE.git(source, "config", "core.repositoryformatversion", "1")
                MODULE.git(source, "config", "extensions.partialClone", "fixture")
                MODULE.git(source, "config", "remote.fixture.promisor", "true")
                MODULE.git(source, "config", "remote.fixture.url", str(remote))
                MODULE.git(remote, "config", "uploadpack.allowAnySHA1InWant", "true")
                blob = MODULE.git_oid("blob", b"original license\n")
                missing = source / ".git/objects" / blob[:2] / blob[2:]
                # Only this test's newly created object is removed. Both exact
                # source payload and the separate local promisor remain intact.
                missing.chmod(0o600)
                missing.unlink()
                inventory = lambda: {str(p.relative_to(source)): p.read_bytes()
                                     for p in (source / ".git").rglob("*") if p.is_file()}
                before = inventory()
                with self.assertRaises(ValueError):
                    MODULE.restore(row["commit"], folder / "refused", local_repo=source, archive_dir=folder)
                self.assertFalse((folder / "refused").exists())
                self.assertEqual(inventory(), before, "lazy fetch modified the original repository")
                # Positive control: the same missing object really is fetchable
                # from the disposable LOCAL promisor if the explicit ban is off.
                env = MODULE.git_env()
                env.pop("GIT_NO_LAZY_FETCH")
                command = MODULE.git_command(source, "cat-file", "-e", blob)
                command.remove("--no-lazy-fetch")
                control = subprocess.run(command,
                                         cwd=source, env=env, capture_output=True, timeout=30)
                self.assertEqual(control.returncode, 0, "fixture did not exercise a usable promisor")
                self.assertNotEqual(inventory(), before, "positive control did not fetch the missing object")

    @unittest.skipUnless(os.name == "posix" and hasattr(os, "geteuid") and os.geteuid() == 0,
                         "requires Linux root to test a differently owned checkout")
    def test_local_git_exact_command_scope_accepts_different_owner(self):
        with tempfile.TemporaryDirectory() as base:
            folder = Path(base)
            row, metadata, _ = fixture(folder)
            local = folder / "local"
            with mock.patch.object(MODULE, "PINS", metadata):
                MODULE.restore(row["commit"], local, archive_dir=folder, make_git=True)
                raw = MODULE.git(local, "archive", "--format=tar",
                                 "--prefix=RAZVILKA-" + row["commit"] + "/", row["commit"])
                value = json.loads(metadata.read_text())
                value["sources"][0]["uncompressed_archive_size"] = len(raw)
                value["sources"][0]["uncompressed_archive_sha256"] = hashlib.sha256(raw).hexdigest()
                metadata.write_text(json.dumps(value))
                os.chown(local, 65534, 65534)
                os.chown(local / ".git", 65534, 65534)
                untrusted = subprocess.run(["git", "rev-parse", "HEAD"], cwd=local, env=MODULE.git_env(),
                                           capture_output=True)
                self.assertNotEqual(untrusted.returncode, 0, "fixture did not exercise dubious ownership")
                result = MODULE.restore(row["commit"], folder / "restored", local_repo=local, make_git=True)
                self.assertEqual(result["source"], "local-git")
                self.assertNotIn(b"safe.directory=", MODULE.git(local, "config", "--local", "--list"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
