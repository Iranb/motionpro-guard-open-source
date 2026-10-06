#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 MotionPro Guard contributors
"""Audit an allowlisted public tree. Emit file/rule names, never matched values."""
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOP = {"README.md", "LICENSE", "NOTICE.md", "SECURITY.md", ".gitignore",
       "project.example.json", "build.py", "install.py"}
FOLDERS = {"Sources": {".swift"}, "Tests": {".swift", ".py"},
           "scripts": {".py"}, "docs": {".md"}, "automation": {".md", ".json"},
           "examples": {".json", ".yml", ".yaml"}, ".github": {".yml", ".yaml"}}
RULES = {
    "personal_absolute_path": re.compile(r"/(?:Users|Volumes)/[A-Za-z0-9_-]+/"),
    "institution_specific_gateway": re.compile(r"\bvpn\.[a-z0-9.-]+\.edu(?:\.[a-z]+)?\b", re.I),
    "personal_guard_identifier": re.compile(r"\bcom\.[a-z0-9_-]+\.motionpro-guard\b", re.I),
    "runtime_uuid": re.compile(r"\b[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\b", re.I),
    "github_access_token": re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})\b"),
    "cloud_access_key": re.compile(r"\bAKIA[A-Z0-9]{16}\b"),
    "private_key": re.compile(r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----"),
    "credential_bearing_url": re.compile(r"https?://[^\s/]+:[^\s/]+@"),
}


def permitted(relative):
    if relative.as_posix() in TOP:
        return True
    parts = relative.parts
    return len(parts) > 1 and parts[0] in FOLDERS and relative.suffix in FOLDERS[parts[0]]


def public_files():
    if (ROOT / ".git").is_dir():
        result = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT,
                                stdout=subprocess.PIPE, check=True)
        return [Path(x.decode()) for x in result.stdout.split(b"\0") if x]
    ignored = {"__pycache__", "dist", "artifacts", "signing", "releases", ".git"}
    return [p.relative_to(ROOT) for p in ROOT.rglob("*") if p.is_file()
            and not any(x in ignored for x in p.relative_to(ROOT).parts)
            and p.name != "project.local.json" and p.suffix != ".pyc"]


def audit(files):
    findings = []
    for relative in sorted(files):
        path = ROOT / relative
        if not permitted(relative) or path.is_symlink():
            findings.append({"file": relative.as_posix(), "rule": "not_in_source_allowlist"})
            continue
        data = path.read_bytes()
        try:
            text = data.decode("utf-8")
        except UnicodeError:
            findings.append({"file": relative.as_posix(), "rule": "non_text_file"})
            continue
        for name, pattern in RULES.items():
            if pattern.search(text):
                findings.append({"file": relative.as_posix(), "rule": name})
    return findings


def main():
    files = public_files()
    findings = audit(files)
    print(json.dumps({"files_checked": len(files), "findings": findings,
                      "passed": not findings}, ensure_ascii=False, indent=2))
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
