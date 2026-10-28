#!/usr/bin/env python3
"""
Quick-launch script located at workspace root.
Allows running the EWB Phishing URL Awareness Checker directly without cd'ing first.
"""
import os
import sys

# Change working directory to phishing-url-awareness folder
PROJECT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "phishing-url-awareness")
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

os.chdir(PROJECT_DIR)

from phishing_checker import main

if __name__ == "__main__":
    main()
