#!/bin/env bash
cd "$(dirname "$0")"
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
mkdocs serve

