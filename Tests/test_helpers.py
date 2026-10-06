# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 MotionPro Guard contributors
"""Synthetic helper tests. Never query the installed client or real Keychain."""
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))
import build
import manual_attempt as manual
import preflight
import release_audit


class ConfigurationTests(unittest.TestCase):
    def write_config(self, value):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        path = Path(folder.name) / "config.json"
        path.write_text(json.dumps(value))
        return path

    def test_valid_gateway(self):
        self.assertEqual(build.configuration(self.write_config({"gateway": "VPN.Example.org"})), "vpn.example.org")

    def test_credentials_rejected(self):
        with self.assertRaises(ValueError):
            build.configuration(self.write_config({"gateway": "vpn.example.org", "password": "dummy"}))

    def test_unsafe_gateway(self):
        for value in ["https://vpn.example.org", "vpn.example.org:443", "a\nb", "-bad.example.org", "a..org", ""]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                build.configuration(self.write_config({"gateway": value}))


class StatusTests(unittest.TestCase):
    def test_connected_exit_status_parser(self):
        self.assertEqual(preflight.parse_status("VPN status:2\n"), 2)

    def test_help_and_duplicate_rejected(self):
        for value in ["(0:idle;2:connected)", "VPN status:2\nVPN status:7\n", "VPN status:9"]:
            self.assertIsNone(preflight.parse_status(value))

    def test_snapshot_omits_secret_fields(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "status.json"
            now = 2000000000.0
            path.write_text(json.dumps({"updatedAt": now - preflight.SWIFT_EPOCH, "state": "connected",
                                        "password": "synthetic-secret", "otp": "synthetic-code"}))
            result = preflight.snapshot_summary(path, now)
            self.assertTrue(result["fresh"])
            self.assertNotIn("password", result)
            self.assertNotIn("otp", result)

    def test_phase_progress_visible_without_arbitrary_text(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "status.json"
            path.write_text(json.dumps({"state": "recovering", "recoveryBusy": True,
                "lastProgressAt": 100.0, "stateDeadline": 200.0, "waitReason": "waiting_tunnel",
                "detail": "synthetic-private-description"}))
            result = preflight.snapshot_summary(path, 1000000000.0)
            self.assertTrue(result["recoveryBusy"])
            self.assertEqual(result["stateDeadline"], 200.0)
            self.assertEqual(result["waitReason"], "waiting_tunnel")
            self.assertNotIn("detail", result)


class ManualBudgetTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.root = Path(self.folder.name)
        self.now = 2000000000.0

    def begin(self):
        return manual.operate("begin", root=self.root, now=self.now)["attempt_id"]

    def finish(self, attempt, outcome):
        return manual.operate("finish", root=self.root, now=self.now, attempt_id=attempt, outcome=outcome)

    def test_pending_attempt_blocks_second_submission(self):
        self.begin()
        with self.assertRaises(manual.Refused):
            self.begin()

    def test_two_failures_hold_and_preserve_budget(self):
        first = self.begin()
        self.finish(first, "failure")
        second = self.begin()
        self.finish(second, "unknown")
        policy = manual.get_policy(self.root)
        self.assertTrue(policy["manualHold"])
        self.assertEqual(policy["consecutiveFailures"], 2)
        self.assertEqual(len(policy["submissions"]), 2)
        with self.assertRaises(manual.Refused):
            self.begin()

    def test_success_does_not_increment_auto_count(self):
        attempt = self.begin()
        self.finish(attempt, "success")
        self.assertIsNone(manual.get_policy(self.root).get("confirmedSuccessCount"))

    def test_finish_idempotent(self):
        attempt = self.begin()
        self.finish(attempt, "failure")
        self.finish(attempt, "failure")
        self.assertEqual(manual.get_policy(self.root)["consecutiveFailures"], 1)

    def test_corrupt_policy_not_replaced(self):
        path = self.root / "recovery-policy.json"
        path.write_text("invalid")
        with self.assertRaises(manual.Refused):
            self.begin()
        self.assertEqual(path.read_text(), "invalid")


class PublicationTests(unittest.TestCase):
    def test_source_allowlist(self):
        self.assertTrue(release_audit.permitted(Path("Sources/Engine.swift")))
        self.assertTrue(release_audit.permitted(Path("skills/motionpro-vpn-access/SKILL.md")))
        self.assertTrue(release_audit.permitted(Path("skills/motionpro-vpn-access/agents/openai.yaml")))
        for path in ["signing/identity.json", "VSite.plist", "events/example.jsonl", "project.local.json", "dist/example.app"]:
            self.assertFalse(release_audit.permitted(Path(path)))
        for path in ["skills/motionpro-vpn-access/environment.local.json",
                     "skills/motionpro-vpn-access/references/local-environment.md",
                     "skills/motionpro-vpn-access/scripts/private.json"]:
            self.assertFalse(release_audit.permitted(Path(path)))


if __name__ == "__main__":
    unittest.main()
