#!/usr/bin/env python3
"""Run every script test: scan.py against injected repos, probe.py against local servers.

Each rule has a case that breaks the thing on purpose and watches the rule fire,
and each script has a clean fixture that must produce zero findings. A check
nobody has seen fail is asserted, not tested; a check that flags honest code
teaches people to skim.
"""

import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent

if __name__ == "__main__":
    suite = unittest.defaultTestLoader.discover(str(HERE), pattern="test_*.py", top_level_dir=str(HERE))
    result = unittest.TextTestRunner(verbosity=1).run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
