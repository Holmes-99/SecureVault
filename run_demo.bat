@echo off
rem one-click demo: the whole scenario + what the attacker sees on the network
cd /d "%~dp0"
if not exist .venv (
    echo setting up the environment, first time only...
    py -m venv .venv
    call .venv\Scripts\activate.bat
    pip install -q -r requirements.txt
) else (
    call .venv\Scripts\activate.bat
)
python tools\run_demo.py --wire --pause
pause
