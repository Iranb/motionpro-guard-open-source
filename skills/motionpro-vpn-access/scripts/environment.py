#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 MotionPro Guard contributors
"""Load a local non-secret profile; never infer authority from its existence."""
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
KEYS = {"support_directory", "app_relative_path", "bundle_identifier",
        "main_job_label", "watchdog_job_label"}


class ProfileError(Exception):
    pass


class Refused(ProfileError):
    pass


def load_profile(path=None, home=None):
    path = ROOT / "environment.local.json" if path is None else Path(path)
    home = Path.home() if home is None else Path(home)
    try:
        if path.is_symlink() or path.stat().st_size > 4096:
            raise ProfileError("invalid_environment_profile")
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise ProfileError("environment_profile_missing")
    except (OSError, ValueError, UnicodeError):
        raise ProfileError("invalid_environment_profile")
    if not isinstance(value, dict) or set(value) != KEYS or not all(isinstance(v, str) for v in value.values()):
        raise ProfileError("invalid_environment_profile")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,79}", value["support_directory"]):
        raise ProfileError("invalid_support_directory")
    relative = Path(value["app_relative_path"])
    if (relative.is_absolute() or len(relative.parts) != 2 or relative.parts[0] != "Applications"
            or not relative.name.endswith(".app") or ".." in relative.parts):
        raise ProfileError("invalid_app_relative_path")
    for key in ("bundle_identifier", "main_job_label", "watchdog_job_label"):
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{2,159}", value[key]):
            raise ProfileError("invalid_job_identity")
    if value["main_job_label"] == value["watchdog_job_label"]:
        raise ProfileError("duplicate_job_identity")
    return {**value, "support": home / "Library/Application Support" / value["support_directory"],
            "app": home / relative, "agents": home / "Library/LaunchAgents"}
