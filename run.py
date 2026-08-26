#!/usr/bin/env python3
"""
HashSentry — Root Launcher
===========================
Allows direct execution via `python run.py`.
"""

import sys
import os

# Ensure project root is in python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from hashsentry.cli import main

if __name__ == "__main__":
    main()
