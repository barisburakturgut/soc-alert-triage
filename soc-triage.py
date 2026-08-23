#!/usr/bin/env python3
"""
SOC Alert Triage Engine - command-line entry point.

    python soc-triage.py --help

Written by Baris Burak Turgut. MIT License.
Provided "AS IS", without warranty of any kind - see LICENSE.
"""

import sys

if sys.version_info < (3, 8):
    sys.exit("Python 3.8 or newer is required.")

from triage.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
