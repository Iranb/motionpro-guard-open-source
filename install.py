#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 MotionPro Guard contributors
"""Explicit first install and login-job control for the OSS app only."""
import argparse
import fcntl
import json
import os
import plistlib
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

LABEL = "org.motionproguard.app"
APP = Path.home() / "Applications/MotionPro Guard OSS.app"
SUPPORT = Path.home() / "Library/Application Support/MotionProGuardOSS"
AGENTS = Path.home() / "Library/LaunchAgents"
DOMAIN = "gui/" + str(os.getuid())


def command(args, check=True):
    result = subprocess.run(args, capture_output=True, text=True, timeout=15)
    if check and result.returncode:
        raise RuntimeError("command_refused:" + Path(args[0]).name)
    return result


def loaded(label):
    return command(["launchctl", "list", label], False).returncode == 0


def other_guards():
    output = command(["launchctl", "list"]).stdout
    found = []
    for line in output.splitlines():
        fields = line.split()
        if len(fields) == 3:
            label = fields[-1]
            compact = re.sub(r"[^a-z]", "", label.lower())
            if "motionproguard" in compact and label not in (LABEL, LABEL + ".watchdog"):
                found.append(label)
    return found


def verify(app):
    info = plistlib.loads((app / "Contents/Info.plist").read_bytes())
    fingerprint = info.get("GuardSigningCertificateSHA1", "")
    gateway = info.get("GuardGateway", "")
    if info.get("CFBundleIdentifier") != LABEL or not re.fullmatch(r"[0-9A-Fa-f]{40}", fingerprint):
        raise RuntimeError("Install requires this OSS app signed with your own persistent certificate")
    if not gateway or gateway.endswith((".example.org", ".invalid")):
        raise RuntimeError("Configure your authorized VPN gateway before installation")
    requirement = f'=identifier "{LABEL}" and certificate leaf = H"{fingerprint}"'
    command(["codesign", "--verify", "--deep", "--strict", "-R", requirement, str(app)])


def job_definitions():
    binary = APP / "Contents/MacOS/MotionProGuard"
    logs = Path.home() / "Library/Logs/MotionProGuardOSS"
    return [dict(Label=LABEL, ProgramArguments=[str(binary)], RunAtLoad=True, KeepAlive=True,
        ThrottleInterval=30, ProcessType="Interactive", LimitLoadToSessionType="Aqua",
        StandardOutPath=str(logs / "guard.stdout.log"), StandardErrorPath=str(logs / "guard.stderr.log")),
        dict(Label=LABEL + ".watchdog", ProgramArguments=[str(binary), "--watchdog"], RunAtLoad=True,
        StartInterval=60, ProcessType="Background", LimitLoadToSessionType="Aqua",
        StandardOutPath="/dev/null", StandardErrorPath=str(logs / "watchdog.stderr.log"))]


def atomic_write(path, data):
    fd, temp = tempfile.mkstemp(prefix=".guard-install-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            os.fchmod(handle.fileno(), 0o600)
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--install", type=Path, metavar="APP", help="First install only; starts no jobs")
    group.add_argument("--enable-jobs", action="store_true")
    group.add_argument("--disable-jobs", action="store_true")
    args = parser.parse_args()
    if not (args.install or args.enable_jobs or args.disable_jobs):
        print(json.dumps({"appInstalled": APP.is_dir(), "guardJobLoaded": loaded(LABEL),
            "watchdogJobLoaded": loaded(LABEL + ".watchdog"), "otherGuardDetected": bool(other_guards())}))
        return
    if (args.install or args.enable_jobs) and other_guards():
        raise SystemExit("Another Guard installation is present; coordinate it explicitly before enabling this one")
    SUPPORT.mkdir(parents=True, exist_ok=True, mode=0o700)
    with (SUPPORT / "recovery-control.lock").open("a+b") as control:
        os.fchmod(control.fileno(), 0o600)
        try:
            fcntl.flock(control, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise SystemExit("Recovery is active; wait for it to finish")
        if args.install:
            if APP.exists() or loaded(LABEL) or loaded(LABEL + ".watchdog"):
                raise SystemExit("Existing installation preserved; this helper does not replace or migrate installations")
            verify(args.install)
            APP.parent.mkdir(parents=True, exist_ok=True)
            shutil.copytree(args.install, APP)
            verify(APP)
            policy = SUPPORT / "recovery-policy.json"
            if not policy.exists():
                value = dict(enabled=False, submissions=[], consecutiveFailures=0, successCount=0, manualHold=False)
                atomic_write(policy, json.dumps(value).encode())
            print("Installed with automatic recovery disabled. Complete local enrollment before enabling it.")
            return
        if args.disable_jobs:
            path = SUPPORT / "status.json"
            if path.exists():
                status = json.loads(path.read_text())
                if status.get("recoveryBusy") or status.get("profileMutationActive"):
                    raise SystemExit("Recovery or configuration transaction active; jobs retained")
            for label in (LABEL + ".watchdog", LABEL):
                if loaded(label):
                    command(["launchctl", "bootout", DOMAIN + "/" + label])
            print("Only OSS Guard login jobs unloaded; VPN client, retry history and credentials retained.")
            return
        verify(APP)
        AGENTS.mkdir(parents=True, exist_ok=True)
        logs = Path.home() / "Library/Logs/MotionProGuardOSS"
        logs.mkdir(parents=True, exist_ok=True, mode=0o700)
        for job in job_definitions():
            path = AGENTS / (job["Label"] + ".plist")
            if not loaded(job["Label"]):
                atomic_write(path, plistlib.dumps(job))
                command(["plutil", "-lint", str(path)])
                command(["launchctl", "bootstrap", DOMAIN, str(path)])
        print("OSS Guard login jobs enabled; the saved recovery on/off setting is preserved.")


if __name__ == "__main__":
    main()
