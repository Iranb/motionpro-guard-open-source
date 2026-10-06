# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 MotionPro Guard contributors
"""Run standalone skill tests without polluting repository helper imports."""
import subprocess
import sys
import unittest
from pathlib import Path


class SkillTests(unittest.TestCase):
    def test_standalone_skill_helpers(self):
        script = Path(__file__).resolve().parents[1] / "skills/motionpro-vpn-access/scripts/test_helpers.py"
        result = subprocess.run([sys.executable, str(script)], capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
