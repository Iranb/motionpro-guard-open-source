#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 MotionPro Guard contributors
"""Synthetic skill tests. Never operate a real client, launchctl or Keychain."""
import fcntl
import json
import os
import plistlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import environment
import handover
import manual_attempt as manual
import preflight


class Fixture(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.home = Path(self.folder.name)
        self.config = self.home / "profile.json"
        self.value = json.loads((environment.ROOT / "environment.example.json").read_text())
        self.config.write_text(json.dumps(self.value))
        self.profile = environment.load_profile(self.config, self.home)
        self.root = self.profile["support"]
        self.root.mkdir(parents=True)
        self.now = 2000000000.0
        self.policy = manual.default_policy()
        self.policy["enabled"] = True
        self.policy["submissions"] = [self.now - preflight.SWIFT_EPOCH - 10]
        manual.atomic_json(self.root / "recovery-policy.json", self.policy)
        manual.atomic_json(self.root / "status.json", {"recoveryBusy": False, "profileMutationActive": False})
        app = self.profile["app"]
        (app / "Contents").mkdir(parents=True)
        (app / "Contents/Info.plist").write_bytes(plistlib.dumps({"CFBundleIdentifier": self.value["bundle_identifier"]}))
        self.profile["agents"].mkdir(parents=True)
        for index, label in enumerate(handover.labels(self.profile)):
            args = [str(app / "Contents/MacOS/MotionProGuard")]
            if index:
                args.append("--watchdog")
            (self.profile["agents"] / (label + ".plist")).write_bytes(plistlib.dumps({"Label": label, "ProgramArguments": args}))
        self.loaded = {"main_loaded": True, "watchdog_loaded": True, "other_guard_loaded": False}
        self.calls = []

    def fake_command(self, args):
        self.calls.append(args)
        if args[0] == "/usr/bin/codesign":
            return b""
        if args[1] == "bootout":
            label = args[-1].split("/")[-1]
            key = "main_loaded" if label == self.value["main_job_label"] else "watchdog_loaded"
            self.loaded[key] = False
        elif args[1] == "bootstrap":
            label = Path(args[-1]).stem
            key = "main_loaded" if label == self.value["main_job_label"] else "watchdog_loaded"
            self.loaded[key] = True
        else:
            raise AssertionError("unexpected mock command")
        return b""

    def simulate(self, status=7):
        stack = patch.multiple(handover, command=self.fake_command,
                               job_state=lambda _: dict(self.loaded),
                               query_vendor=lambda: {"status_code": status})
        stack.start()
        self.addCleanup(stack.stop)


class EnvironmentTests(Fixture):
    def test_missing_profile_fails_closed(self):
        with self.assertRaises(environment.ProfileError):
            environment.load_profile(self.home / "missing.json", self.home)

    def test_no_credentials_or_traversal(self):
        for key, value in [("password", "synthetic"), ("support_directory", "../escape"),
                           ("app_relative_path", "Applications/../Wrong.app"),
                           ("main_job_label", "../../arbitrary")]:
            with self.subTest(key=key), self.assertRaises(environment.ProfileError):
                self.config.write_text(json.dumps({**self.value, key: value}))
                environment.load_profile(self.config, self.home)

    def test_local_symlink_profile_rejected(self):
        link = self.home / "link.json"
        link.symlink_to(self.config)
        with self.assertRaises(environment.ProfileError):
            environment.load_profile(link, self.home)


class StatusTests(Fixture):
    def test_vendor_status_not_shell_exit(self):
        self.assertEqual(preflight.parse_status("VPN status:2\n"), 2)
        self.assertEqual(preflight.decision(6), ("tunnel_connected_check_target", 0))
        self.assertIsNone(preflight.parse_status("VPN status:2\nVPN status:7\n"))

    def test_snapshot_whitelist_and_null_readiness(self):
        value = {"updatedAt": self.now - preflight.SWIFT_EPOCH, "state": "connected",
                 "password": "dummy-private", "otp": "dummy-code", "title": "dummy-account",
                 "recoveryBusy": False, "stateDeadline": 100.0, "waitReason": "waiting_tunnel"}
        manual.atomic_json(self.root / "status.json", value)
        result = preflight.snapshot_summary(self.root / "status.json", self.now)
        self.assertTrue(result["fresh"])
        self.assertIsNone(result["credentialReady"])
        self.assertEqual(result["stateDeadline"], 100.0)
        self.assertTrue({"password", "otp", "title"}.isdisjoint(result))


class HandoverTests(Fixture):
    def test_inspect_has_no_mutation(self):
        self.simulate()
        before = (self.root / "recovery-policy.json").read_bytes()
        result = handover.operate("inspect", self.profile)
        self.assertTrue(result["main_loaded"])
        self.assertEqual((self.root / "recovery-policy.json").read_bytes(), before)
        self.assertFalse((self.root / "agent-handover.json").exists())
        self.assertTrue(all(call[0] == "/usr/bin/codesign" for call in self.calls))

    def test_connected_transition_and_unknown_refuse_pause(self):
        self.simulate()
        for status in (None, 1, 2, 3, 4, 5, 6):
            with self.subTest(status=status), patch.object(handover, "query_vendor", return_value={"status_code": status}):
                with self.assertRaises(manual.Refused):
                    handover.operate("pause", self.profile)
        self.assertTrue(self.loaded["main_loaded"])

    def test_recovery_lock_and_busy_refuse_stop(self):
        self.simulate()
        with (self.root / "recovery-control.lock").open("w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaises(manual.Refused):
                handover.operate("pause", self.profile)
        manual.atomic_json(self.root / "status.json", {"recoveryBusy": True})
        with self.assertRaises(manual.Refused):
            handover.operate("pause", self.profile)
        self.assertTrue(self.loaded["main_loaded"])

    def test_other_guard_refuses_and_wrong_job_never_stopped(self):
        self.simulate()
        self.loaded["other_guard_loaded"] = True
        with self.assertRaises(manual.Refused):
            handover.operate("pause", self.profile)
        self.loaded["other_guard_loaded"] = False
        path = self.profile["agents"] / (self.value["main_job_label"] + ".plist")
        path.write_bytes(plistlib.dumps({"Label": self.value["main_job_label"], "ProgramArguments": ["/bin/false"]}))
        with self.assertRaises(manual.Refused):
            handover.operate("pause", self.profile)
        self.assertTrue(self.loaded["main_loaded"])

    def test_pause_submit_finish_resume_preserves_budget_and_hold(self):
        self.simulate()
        result = handover.operate("pause", self.profile)
        self.assertTrue(result["previous_enabled"])
        stops = [c[-1] for c in self.calls if c[0] == "/bin/launchctl" and c[1] == "bootout"]
        self.assertTrue(stops[0].endswith(self.value["watchdog_job_label"]))
        self.assertFalse(manual.get_policy(self.root)["enabled"])
        handover.require_paused(self.profile)
        attempt = manual.operate("begin", root=self.root, now=self.now)["attempt_id"]
        with self.assertRaises(manual.Refused):
            handover.operate("resume", self.profile)
        manual.operate("finish", root=self.root, now=self.now, attempt_id=attempt, outcome="unknown")
        handover.operate("resume", self.profile)
        policy = manual.get_policy(self.root)
        self.assertTrue(policy["enabled"])
        self.assertEqual(len(policy["submissions"]), 2)
        self.assertEqual(policy["consecutiveFailures"], 1)
        self.assertIsNone(policy.get("confirmedSuccessCount"))
        self.assertTrue(self.loaded["main_loaded"])
        self.assertTrue(self.loaded["watchdog_loaded"])

    def test_original_disabled_jobs_stay_disabled_and_failure_hold_stays(self):
        self.simulate()
        self.loaded["watchdog_loaded"] = False
        self.policy.update(enabled=False, manualHold=True, consecutiveFailures=2)
        manual.atomic_json(self.root / "recovery-policy.json", self.policy)
        handover.operate("pause", self.profile)
        handover.operate("resume", self.profile)
        policy = manual.get_policy(self.root)
        self.assertFalse(policy["enabled"])
        self.assertTrue(policy["manualHold"])
        self.assertEqual(policy["consecutiveFailures"], 2)
        self.assertFalse(self.loaded["watchdog_loaded"])

    def test_missing_policy_not_recreated(self):
        self.simulate()
        (self.root / "recovery-policy.json").unlink()
        with self.assertRaises(manual.Refused):
            handover.operate("pause", self.profile)
        self.assertFalse((self.root / "recovery-policy.json").exists())

    def test_partial_stop_can_resume_original_jobs(self):
        self.simulate()
        value = {"profile_digest": handover.profile_digest(self.profile), "previous_enabled": True,
                 "main_loaded": True, "watchdog_loaded": True}
        handover.save_receipt(self.profile, value, "pausing")
        self.loaded["watchdog_loaded"] = False
        handover.operate("resume", self.profile)
        self.assertTrue(self.loaded["main_loaded"])
        self.assertTrue(self.loaded["watchdog_loaded"])


class ManualBudgetTests(Fixture):
    def setUp(self):
        super().setUp()
        self.policy.update(enabled=False, submissions=[])
        manual.atomic_json(self.root / "recovery-policy.json", self.policy)

    def test_pending_idempotency_two_failure_hold(self):
        first = manual.operate("begin", root=self.root, now=self.now)["attempt_id"]
        with self.assertRaises(manual.Refused):
            manual.operate("begin", root=self.root, now=self.now)
        for _ in range(2):
            manual.operate("finish", root=self.root, now=self.now, attempt_id=first, outcome="failure")
        second = manual.operate("begin", root=self.root, now=self.now)["attempt_id"]
        manual.operate("finish", root=self.root, now=self.now, attempt_id=second, outcome="unknown")
        self.assertEqual(manual.get_policy(self.root)["consecutiveFailures"], 2)
        self.assertTrue(manual.get_policy(self.root)["manualHold"])
        with self.assertRaises(manual.Refused):
            manual.operate("begin", root=self.root, now=self.now)

    def test_corrupt_policy_preserved(self):
        path = self.root / "recovery-policy.json"
        path.write_text("invalid")
        with self.assertRaises(manual.Refused):
            manual.operate("begin", root=self.root, now=self.now)
        self.assertEqual(path.read_text(), "invalid")


if __name__ == "__main__":
    unittest.main()
