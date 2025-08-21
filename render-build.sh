#!/usr/bin/env bash
set -euo pipefail
python --version
python -m pip install --upgrade pip setuptools wheel
python -m pip install -r requirements.txt