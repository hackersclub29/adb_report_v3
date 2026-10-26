# PowerShell setup + test + sample run (Windows PowerShell 5.1 or PowerShell 7+)
$ErrorActionPreference = "Stop"
python --version
python -m venv .venv
. .\.venv\Scripts\Activate.ps1
python -m pip install -r requirements-dev.txt
python -m pytest -q tests
# Put adb.exe (platform-tools) next to adb_report.py, on PATH, or pass --adb "C:\platform-tools\adb.exe"
python adb_report.py --list-modules
Write-Host "Run:  python adb_report.py --profile deep"
