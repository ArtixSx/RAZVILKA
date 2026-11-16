#!/usr/bin/env python3
import hashlib
import importlib.util
import pathlib
import tempfile
import unittest
import sys

# Validation must not leave bytecode in the scripts copied into the package.
sys.dont_write_bytecode = True

spec = importlib.util.spec_from_file_location("release_notes", pathlib.Path(__file__).with_name("prepare-release-notes.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ReleaseNotesTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        self.notes = self.root / "docs/releases/1.2.3.md"
        self.notes.parent.mkdir(parents=True)
        (self.root / "docs/INSTALL_RU.md").write_text("install", encoding="utf-8")
        self.notes.write_text("Новые возможности\n[Установка](../INSTALL_RU.md#steps)\n[Source](https://example.com)", encoding="utf-8")
        self.names = ["RAZVILKA-1.2.3-entware.tar.gz", "RAZVILKA-1.2.3-entware.zip"]
        self.names += [f"dist/razvilka-linux-{arch}" for arch in ("amd64", "arm64", "mips", "mipsle")]
        for name in self.names:
            path = self.root / name
            path.parent.mkdir(exist_ok=True)
            path.write_bytes(name.encode())

    def render(self, **options):
        values = dict(root=self.root, version="1.2.3", commit="a" * 40, repository="Owner/Project", notes=self.notes)
        values.update(options)
        return module.prepare(**values)

    def test_actual_files_and_pinned_links(self):
        body = self.render()
        self.assertIn("Новые возможности", body)
        self.assertIn("blob/" + "a" * 40 + "/docs/INSTALL_RU.md#steps", body)
        self.assertIn("[Source](https://example.com)", body)
        for name in self.names:
            digest = hashlib.sha256(name.encode()).hexdigest()
            self.assertIn(digest + "  " + pathlib.Path(name).name, body)
        changed = self.root / self.names[0]
        changed.write_bytes(b"a different actual build")
        self.assertNotEqual(body, self.render())
        self.assertIn(hashlib.sha256(changed.read_bytes()).hexdigest(), self.render())

    def test_missing_or_empty_build_refuses(self):
        path = self.root / self.names[0]
        path.unlink()
        with self.assertRaises(ValueError):
            self.render()
        path.write_bytes(b"")
        with self.assertRaises(ValueError):
            self.render()

    def test_bad_identity_and_document_escape_refuse(self):
        for options in [dict(version="../../other"), dict(commit="main"), dict(repository="owner/repo/other")]:
            with self.subTest(options=options), self.assertRaises(ValueError):
                self.render(**options)
        self.notes.write_text("[outside](../../../outside.md)", encoding="utf-8")
        with self.assertRaises(ValueError):
            self.render()
        self.notes.write_text("[missing](../not-present.md)", encoding="utf-8")
        with self.assertRaises(ValueError):
            self.render()


if __name__ == "__main__":
    unittest.main()
