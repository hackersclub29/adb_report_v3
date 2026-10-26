# adb_report v3.0

Read-only, runtime-adaptive Android deep enumeration over ADB. Upgrade of `adb_report.py v2.0`; same entry point (`python adb_report.py`), same core flags, much wider coverage. Standard library only (Python 3.9+).

## Setup
1. Install Python 3.9+ and Android platform-tools (`adb`). Put `adb`/`adb.exe` next to `adb_report.py`, on PATH, or pass `--adb`.
2. Enable USB debugging on the device and accept the RSA prompt. No root, no agent, no bootloader unlock.
3. Optional host tools for APK analysis: `apksigner`, `apkanalyzer`, `apktool`, `jadx`, a MobSF server (auto-detected, or `--apksigner PATH` etc.).

Windows / PowerShell: `.\setup.ps1` (creates a venv, runs the tests). Run with `python adb_report.py ...`; paths with spaces need normal PowerShell quoting. The device command is always passed as one argv element (no host shell), so PowerShell quoting never reaches the device.

## Examples
```powershell
python adb_report.py                                   # deep profile (default)
python adb_report.py --profile quick -s R58M123ABC
python adb_report.py --profile exhaustive --out-dir C:\cases\phone1
python adb_report.py --modules identity,network,logs --log-lines 20000
python adb_report.py --skip-modules bugreport,storage_index --profile exhaustive
python adb_report.py --hash-apps --full-perms --json phone.json -o phone.md        # v2-style
python adb_report.py --pull-apks apks --analyze-apks --jadx-decompile --apktool-decode
python adb_report.py --storage-index /sdcard --storage-depth 6 --storage-hash --storage-hash-max-mb 25
python adb_report.py --baseline C:\cases\phone1\report.json --out-dir C:\cases\phone1_later
python adb_report.py --mobsf-url http://127.0.0.1:8000 --mobsf-key KEY --analyze-apks
python adb_report.py --list-modules
```

## Profiles
| Profile | Runs |
|---|---|
| `quick` | identity, config, security, hardware, storage, power, accounts, packages (+details), app security, runtime, network, correlation; current user only |
| `deep` (default) | quick + dynamic service dumps + logcat buffers; all users; permission catalog |
| `exhaustive` | deep + **every** discovered dumpsys service, all log buffers (full), all-package app-ops, all-APK device hashes, shared-storage index, `adb bugreport`, APK pull (third-party; `--apk-scope all` for system), host analysis if tools exist. Can take a long time. |

`--modules` selects exactly those modules; flags (`--logs`, `--bugreport`, `--storage-index`, `--pull-apks`, `--analyze-apks`) add modules to any profile; `--skip-modules` removes.
Timeouts/retries: `--timeout`, `--long-timeout`, `--service-timeout`, `--retries`, `--retry-delay`. Progress goes to stderr (`-q` silences, `-v` echoes every command).

## Output (`--out-dir`, default `adb_report_<serial>_<timestamp>/`)
`report.md` (findings, sections, command inventory, what was/was not collected) · `report.json` (structured, schema 3.0) · `commands.json` (every command: id, argv, exit code, status, duration, raw file) · `raw/` (stdout/stderr per command) · `manifest.json` (SHA-256 + timestamps of every artifact) · optional `storage_index.csv`, `apks/`, `apk_analysis/`, `bugreport/`.

Command statuses: `ok` (`*` partial output despite non-zero exit), `empty` (ran, no output - never treated as failure), `unsupported`, `denied`, `timeout`, `failed`, `blocked` (refused by the read-only guard, never sent).

## Read-only guarantee
Every device shell command passes a guard that refuses writes/redirections, `rm/mv/setprop/svc/input/...`, `settings put`, mutating `pm/am/cmd` verbs, `logcat -c`, `dumpsys ... --reset/force-idle`, etc.; only allow-listed host `adb` subcommands run. This is tested (`tests/test_adb.py`, plus an integration test that replays every command sent in an exhaustive run through the guard). The one unavoidable side effect: `adb bugreport` makes the device's dumpstate write its own temporary archive. Skip it with `--skip-modules bugreport`.

## Notes on changes from v2
- `--redact` and all masking/omission were **removed** as requested (flag is accepted and ignored). Reports contain serials, MACs, SSIDs, accounts, etc. - treat artifacts as sensitive.
- No vendor/version-specific package lists or property names; installer/system classification uses partitions, flags and runtime discovery.
- Fixed v2 issues: silent discard of stderr/exit code, `''` meaning both "empty" and "failed", brittle quoting, single-user assumptions, merged per-user permission state, fixed-role list.

## Verification status (be aware)
88 unit/integration tests pass (`TEST_RESULTS.txt`) against a **mocked** ADB transport. The tool has **not** been run against a physical device in this environment, and the Windows tests are simulations of Windows path/quoting behaviour on Linux; please run `pytest` natively in PowerShell and a `--profile quick` run on your phone first. Dumpsys formats differ across Android builds, so some parsers (alarms, notifications, exit-info, netstats, resolver tables, battery stats) are best-effort; raw output is always preserved and parse problems are listed under *Parser diagnostics*.
