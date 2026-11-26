"""Offline generator contracts; never start an engine, connect, or edit source."""
import hashlib
import json
from pathlib import Path
import stat
import tempfile
import unittest

import prepare_overlay as qa


class OverlayContracts(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.source = self.base / "source"
        self.source.mkdir()
        self.output = self.base / "generated"
        self.manifest = json.loads((qa.PACKAGE / "source-pins.json").read_text())
        original = qa.PACKAGE.parents[2]
        self.originals = {}
        for name in self.manifest["source_sha256"]:
            data = (original / name).read_bytes()
            path = self.source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            self.originals[name] = data

    def test_current_source_hooks_and_payloads_are_only_virtual(self):
        overlay = qa.prepare(self.source, self.output)
        mapping = json.loads(overlay.read_text())["Replace"]
        self.assertEqual(len(mapping), len(self.originals) + len(qa.PAYLOADS))
        for name, data in self.originals.items():
            self.assertEqual((self.source / name).read_bytes(), data)
            self.assertNotEqual(Path(mapping[str(self.source / name)]).read_bytes(), data)
        for name, payload in qa.PAYLOADS.items():
            self.assertFalse((self.source / name).exists())
            self.assertEqual(Path(mapping[str(self.source / name)]).read_bytes(),
                             (qa.PACKAGE / "payload" / payload).read_bytes().replace(b"\r\n", b"\n"))
        checker = Path(mapping[str(self.source / "internal/dataplane/nodecheck.go")]).read_text(encoding="utf-8")
        self.assertEqual(checker.count("qaMTBind(qaMTAttempt, session, passport)"), 1)
        self.assertEqual(checker.count("qaMTFinalize(c, parent, request, qaMTAttempt, result, resultErr)"), 1)
        # The new production guard and outer cleanup/cancellation boundaries
        # survive intact, rather than replacing source with the old QA copy.
        for anchor in ("checkNodeResource(ctx", "refuseNodeResourceObservationResult", "defer cancel()"):
            self.assertIn(anchor, checker)
        self.assertTrue((self.output / "hooks.diff").read_text(encoding="utf-8").startswith("--- internal/dataplane/nodecheck.go"))
        if __import__("os").name != "nt":
            self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o700)
            self.assertTrue(all(stat.S_IMODE(p.stat().st_mode) == 0o600 for p in self.output.iterdir()))

    def test_either_changed_source_pin_refuses_before_writes(self):
        for name in self.originals:
            with self.subTest(name=name):
                path = self.source / name
                path.write_bytes(self.originals[name] + b"\n// stale or unreviewed source\n")
                with self.assertRaisesRegex(ValueError, "source pin"):
                    qa.prepare(self.source, self.output)
                self.assertFalse(self.output.exists())
                path.write_bytes(self.originals[name])

    def test_crlf_conversion_does_not_change_the_reviewed_source_pin(self):
        for name, data in self.originals.items():
            (self.source / name).write_bytes(data.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n"))
        qa.prepare(self.source, self.output)

    def test_old_source_pins_are_retained_but_cannot_authorize_current_source(self):
        self.assertEqual(self.manifest["previous_source_commit"], "616abe95dc59f41d664419ba377a5e1ea1498bae")
        for name, data in self.originals.items():
            digest = hashlib.sha256(data.replace(b"\r\n", b"\n")).hexdigest()
            self.assertEqual(digest, self.manifest["source_sha256"][name])
            self.assertNotEqual(digest, self.manifest["previous_sha256"][name])

    def test_occupied_virtual_target_refuses_before_writes(self):
        for name in qa.PAYLOADS:
            with self.subTest(name=name):
                path = self.source / name
                path.write_text("package occupied\n")
                with self.assertRaisesRegex(ValueError, "occupied"):
                    qa.prepare(self.source, self.output)
                self.assertFalse(self.output.exists())
                self.assertEqual(path.read_text(), "package occupied\n")
                path.unlink()

    def test_existing_output_is_never_overwritten_or_reused(self):
        qa.prepare(self.source, self.output)
        before = {p.name: p.read_bytes() for p in self.output.iterdir()}
        with self.assertRaisesRegex(ValueError, "new QA output"):
            qa.prepare(self.source, self.output)
        self.assertEqual(before, {p.name: p.read_bytes() for p in self.output.iterdir()})

    def test_missing_and_ambiguous_hook_are_rejected(self):
        for data in (b"other", b"hook hook"):
            with self.assertRaisesRegex(ValueError, "ambiguous"):
                qa.replace_once(data, b"hook", b"new")
        self.assertEqual(qa.replace_once(b"x hook y", b"hook", b"new"), b"x new y")

    def test_output_cannot_create_qa_packages_inside_production_tree(self):
        with self.assertRaisesRegex(ValueError, ".review-local"):
            qa.prepare(self.source, self.source / "qa-package")
        self.assertFalse((self.source / "qa-package").exists())


if __name__ == "__main__":
    unittest.main()
