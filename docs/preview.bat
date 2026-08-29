@echo off

cd /D "%~dp0"
python -m venv .venv
CALL .venv/Scripts/activate.bat
python -m pip install -r requirements.txt
mkdocs serve
