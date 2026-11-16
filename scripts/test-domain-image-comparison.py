#!/usr/bin/env python3
"""Report contracts only; synthetic logs are never native performance evidence."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).with_name("compare-domain-image-native.sh")
REPORT = SCRIPT.read_text(encoding="utf-8").rsplit("<<'PY'\n", 1)[1].split("\nPY\n", 1)[0]
EXPECTED = "TestDomainTCPOriginalNativeAcceptedFlows"


class ComparisonReport(unittest.TestCase):
    def sample(self, root, index, side, *, passed=True, answer=True, image=None):
        path = root / f"{index:02d}-{side}"
        path.mkdir()
        rc = 0 if passed else 1
        (path / "exit-status.txt").write_text(f"{rc}\n", encoding="utf-8")
        (path / "log-status.txt").write_text("0\n", encoding="utf-8")
        (path / "status.txt").write_text(
            f"publication_budget_seconds=12\ndiagnostic_only=false\nnative_case={EXPECTED}\nchild_exit_status={rc}\n",
            encoding="utf-8",
        )
        (path / "supervisor.json").write_text(json.dumps({"no_overlap_boundary": True}), encoding="utf-8")
        log = ""
        if answer:
            image = side == "candidate" if image is None else image
            counters = "whole-executable-hash:{Calls:2 Bytes:100 Elapsed:1ms}"
            if image:
                counters += " executable-image-capture:{Calls:1 Bytes:50 Elapsed:1ms}"
            log += "actual first DNS answer completed-counter snapshot: map[" + counters + "]\n"
        log += f"--- {'PASS' if passed else 'FAIL'}: {EXPECTED} (1.00s)\n"
        (path / "native.log").write_text(log, encoding="utf-8")

    def run_case(self, cut):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "source-comparison").mkdir()
            (root / "source-comparison/variant.json").write_text(json.dumps({"source_commit": "a" * 40}), encoding="utf-8")
            for index, side in enumerate(["baseline", "candidate", "candidate", "baseline"], 1):
                options = {}
                if cut == "baseline-fails" and index == 1:
                    options["passed"] = False
                if cut == "baseline-uses-image" and index == 1:
                    options["image"] = True
                if cut == "candidate-missing-image" and index == 2:
                    options["image"] = False
                if cut == "candidate-prestart-refusal" and index == 2:
                    options.update(passed=False, answer=False)
                self.sample(root, index, side, **options)
            env = dict(os.environ, DOMAIN_IMAGE_OUTPUT=str(root), DOMAIN_IMAGE_EXPECTED=EXPECTED,
                       DOMAIN_IMAGE_BASELINE="synthetic-current-source-full-SHA-fallback",
                       DOMAIN_IMAGE_CANDIDATE="a" * 40, DOMAIN_IMAGE_SCENARIO="selected")
            result = subprocess.run([sys.executable, "-c", REPORT], env=env, capture_output=True, text=True, timeout=10)
            self.assertIn(result.returncode, (0, 1), result.stderr)
            return result.returncode, json.loads((root / "comparison.json").read_text(encoding="utf-8"))

    def test_all_pass(self):
        rc, report = self.run_case("none")
        self.assertEqual(rc, 0)
        self.assertTrue(report["all_samples_pass"])

    def test_failed_baseline_is_not_acceptance(self):
        rc, report = self.run_case("baseline-fails")
        self.assertEqual(rc, 1)
        self.assertFalse(report["all_samples_pass"])
        self.assertTrue(report["all_candidate_samples_pass"])
        self.assertEqual(report["samples"][0]["status"], "fail")

    def test_wrong_baseline_path_refuses(self):
        rc, report = self.run_case("baseline-uses-image")
        self.assertEqual(rc, 1)
        self.assertFalse(report["samples"][0]["variant_path_valid"])

    def test_candidate_reached_path_must_be_measured(self):
        rc, report = self.run_case("candidate-missing-image")
        self.assertEqual(rc, 1)
        self.assertFalse(report["samples"][1]["variant_path_valid"])

    def test_prestart_failure_is_retained_without_false_path_claim(self):
        rc, report = self.run_case("candidate-prestart-refusal")
        self.assertEqual(rc, 1)
        row = report["samples"][1]
        self.assertEqual(row["status"], "fail")
        self.assertTrue(row["variant_path_valid"])
        self.assertFalse(row["image_path_observed"])


if __name__ == "__main__":
    unittest.main()
