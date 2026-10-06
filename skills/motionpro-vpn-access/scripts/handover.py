#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 MotionPro Guard contributors
"""Inspect by default; explicitly coordinate only the profiled Guard's existing jobs."""
import argparse
import fcntl
import hashlib
import json
import os
import plistlib
import subprocess
import sys
import time
from contextlib import contextmanager

from environment import KEYS, ProfileError, load_profile
from manual_attempt import Refused, atomic_json, get_policy, get_record, guard_stopped_lock
from preflight import query_vendor, read_object

PHASES = {"pausing", "paused", "resuming", "resumed"}


def command(args):
    try:
        result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                timeout=15, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise Refused("local_job_command_unavailable")
    if result.returncode:
        raise Refused("local_job_command_refused")
    return result.stdout


def profile_digest(profile):
    value = {key: profile[key] for key in KEYS}
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def labels(profile):
    return (profile["main_job_label"], profile["watchdog_job_label"])


def job_state(profile):
    own = labels(profile)
    loaded = set()
    for line in command(["/bin/launchctl", "list"]).decode("utf-8", "replace").splitlines():
        parts = line.split()
        if len(parts) == 3:
            loaded.add(parts[-1])
    other = any("motionproguard" in "".join(c for c in name.lower() if c.isalpha())
                for name in loaded - set(own))
    return {"main_loaded": own[0] in loaded, "watchdog_loaded": own[1] in loaded,
            "other_guard_loaded": other}


def verify_jobs(profile):
    app, support = profile["app"], profile["support"]
    if app.is_symlink() or support.is_symlink() or not support.is_dir():
        raise Refused("profile_paths_unavailable_or_redirected")
    try:
        info = plistlib.loads((app / "Contents/Info.plist").read_bytes())
        if info.get("CFBundleIdentifier") != profile["bundle_identifier"]:
            raise Refused("app_identity_mismatch")
        binary = str(app / "Contents/MacOS/MotionProGuard")
        for index, label in enumerate(labels(profile)):
            path = profile["agents"] / (label + ".plist")
            if path.is_symlink() or path.stat().st_size > 65536:
                raise Refused("job_definition_mismatch")
            value = plistlib.loads(path.read_bytes())
            expected = [binary] if index == 0 else [binary, "--watchdog"]
            if value.get("Label") != label or value.get("ProgramArguments") != expected or value.get("Program"):
                raise Refused("job_definition_mismatch")
    except (OSError, ValueError, plistlib.InvalidFileException):
        raise Refused("profile_job_files_unavailable_or_invalid")
    command(["/usr/bin/codesign", "--verify", "--deep", "--strict", str(app)])


def receipt(profile):
    value, state = read_object(profile["support"] / "agent-handover.json")
    if state == "missing":
        return None
    if (not isinstance(value, dict) or value.get("profile_digest") != profile_digest(profile)
            or value.get("phase") not in PHASES
            or any(type(value.get(key)) is not bool for key in
                   ("previous_enabled", "main_loaded", "watchdog_loaded"))):
        raise Refused("invalid_handover_receipt_preserved")
    return value


def save_receipt(profile, value, phase):
    value["phase"] = phase
    atomic_json(profile["support"] / "agent-handover.json", value)


@contextmanager
def recovery_lock(profile):
    path = profile["support"] / "recovery-control.lock"
    if path.is_symlink():
        raise Refused("recovery_lock_redirected")
    fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise Refused("recovery_active_wait_for_completion")
        yield
    finally:
        os.close(fd)


def require_paused(profile):
    verify_jobs(profile)
    value = receipt(profile)
    state = job_state(profile)
    if not value or value["phase"] != "paused" or any(state.values()):
        raise Refused("verified_paused_handover_required")


def operate(action, profile):
    verify_jobs(profile)
    state = job_state(profile)
    value = receipt(profile)
    if action == "inspect":
        exists = (profile["support"] / "recovery-policy.json").is_file()
        policy = get_policy(profile["support"]) if exists else None
        return {**state, "recovery_enabled": policy["enabled"] if policy else None,
                "policy_present": exists,
                "handover_phase": value["phase"] if value else "none"}
    if state["other_guard_loaded"]:
        raise Refused("another_guard_present_coordinate_first")
    root = profile["support"]
    if not (root / "recovery-policy.json").is_file():
        raise Refused("existing_shared_policy_required_no_budget_reset")
    with recovery_lock(profile):
        if action == "pause":
            if value and value["phase"] in ("resuming",):
                raise Refused("incomplete_resume_finish_it_first")
            # Always confirm the actual tunnel before touching Guard jobs.
            if query_vendor()["status_code"] not in (0, 7):
                raise Refused("persistent_disconnection_required")
            snapshot, read_status = read_object(root / "status.json")
            if read_status != "missing" and (snapshot is None or
                    any(snapshot.get(k) is True for k in ("recoveryBusy", "profileMutationActive"))):
                raise Refused("active_or_unknown_recovery_transaction")
            policy = get_policy(root)
            if not value or value["phase"] == "resumed":
                value = {"profile_digest": profile_digest(profile), "previous_enabled": policy["enabled"],
                         "main_loaded": state["main_loaded"], "watchdog_loaded": state["watchdog_loaded"]}
                save_receipt(profile, value, "pausing")
            for index in (1, 0):
                current = job_state(profile)
                key = "watchdog_loaded" if index else "main_loaded"
                if current[key]:
                    command(["/bin/launchctl", "bootout", "gui/" + str(os.getuid()) + "/" + labels(profile)[index]])
            # launchctl may return shortly before the exiting process releases its lock.
            deadline = time.monotonic() + 5
            while True:
                try:
                    with guard_stopped_lock(root):
                        policy = get_policy(root)
                        policy["enabled"] = False
                        atomic_json(root / "recovery-policy.json", policy)
                    break
                except Refused as error:
                    if str(error) != "guard_running_pause_and_quit_first":
                        raise
                    if time.monotonic() >= deadline:
                        raise
                    time.sleep(0.1)
            save_receipt(profile, value, "paused")
            require_paused(profile)
            return {"paused": True, "previous_enabled": value["previous_enabled"],
                    "main_was_loaded": value["main_loaded"], "watchdog_was_loaded": value["watchdog_loaded"]}
        if action != "resume" or not value or value["phase"] == "resumed":
            raise Refused("active_handover_receipt_required")
        record = get_record(root)
        if record and record["outcome"] == "pending":
            raise Refused("unsettled_manual_attempt")
        policy = get_policy(root)
        current = job_state(profile)
        if current["main_loaded"] and value["phase"] == "paused":
            raise Refused("guard_started_outside_handover")
        if current["main_loaded"]:
            if policy["enabled"] != value["previous_enabled"]:
                raise Refused("policy_changed_during_partial_resume")
            save_receipt(profile, value, "resuming")
        else:
            save_receipt(profile, value, "resuming")
            with guard_stopped_lock(root):
                record = get_record(root)
                if record and record["outcome"] == "pending":
                    raise Refused("unsettled_manual_attempt")
                policy = get_policy(root)
                policy["enabled"] = value["previous_enabled"]
                atomic_json(root / "recovery-policy.json", policy)
        for index, key in enumerate(("main_loaded", "watchdog_loaded")):
            if value[key] and not job_state(profile)[key]:
                path = profile["agents"] / (labels(profile)[index] + ".plist")
                command(["/bin/launchctl", "bootstrap", "gui/" + str(os.getuid()), str(path)])
        save_receipt(profile, value, "resumed")
        return {"restored": True, "recovery_enabled": value["previous_enabled"], "failure_hold_preserved": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", nargs="?", default="inspect", choices=("inspect", "pause", "resume"))
    args = parser.parse_args()
    try:
        result = operate(args.action, load_profile())
    except (Refused, ProfileError) as error:
        result = {"refused": str(error)}
    except (OSError, ValueError, UnicodeError):
        result = {"refused": "local_handover_read_or_write_failed"}
    print(json.dumps(result, ensure_ascii=False, indent=2, allow_nan=False))
    return 2 if "refused" in result else 0


if __name__ == "__main__":
    sys.exit(main())
