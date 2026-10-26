"""Command line entry point and orchestration."""
from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

from . import __version__, parsers as P
from .adb import Adb, AdbError, find_adb, pick_device, safe_filename
from . import capabilities, collect_apps as A, collect_device as D, collect_extra as X, collect_network as N
from . import collect_services as S, apk_tools, correlate, findings, report
from .model import Ctx, LEVELS


@dataclass
class Module:
    name: str
    fn: Callable[[Ctx], None]
    level: int
    doc: str


def _packages_module(ctx: Ctx) -> None:
    A.collect_package_paths_hashes(ctx)
    A.collect_permissions_catalog(ctx)
    A.collect_apps_section(ctx)


REGISTRY = [
    Module("identity", D.collect_identity, 0, "device identity, build, OS/API, kernel, uptime"),
    Module("build_config", D.collect_build_config, 0, "properties, build.prop files, system configuration"),
    Module("boot_security", D.collect_boot_security, 0, "verified boot, bootloader, SELinux, kernel hardening, root indicators, admins"),
    Module("hardware", D.collect_hardware, 0, "CPU, GPU, SoC, RAM, memory pressure, frequencies, display, sensors, features, libraries"),
    Module("storage", D.collect_storage_info, 0, "storage, partitions, mounts, filesystems"),
    Module("power", D.collect_power, 0, "battery, charging, thermal"),
    Module("accounts", D.collect_users_accounts, 0, "users, profiles, accounts"),
    Module("packages", _packages_module, 0, "applications: versions, installers, perms, APK paths/hashes, signers, components"),
    Module("app_security", A.collect_app_security, 0, "app-ops, roles, a11y, listeners, admins, VPN, IME, autofill, overlays, review list"),
    Module("services", S.collect_services, 1, "dynamic dumpsys service diagnostics"),
    Module("runtime", S.collect_runtime, 0, "processes, usage, alarms, jobs, exits, DropBox, battery stats"),
    Module("network", N.collect_network, 0, "interfaces, routes, rules, DNS, sockets+UID, accounting, Wi-Fi, Bluetooth"),
    Module("logs", X.collect_logs, 1, "logcat buffers, event log, crash, radio, kernel diagnostics"),
    Module("storage_index", X.collect_storage_index, 2, "shared-storage recursive index (+optional hashes)"),
    Module("apk_extract", apk_tools.collect_apk_extract, 2, "pull APKs (base+splits) and hash on host"),
    Module("apk_analysis", apk_tools.collect_apk_analysis, 2, "apksigner / apkanalyzer / apktool / JADX / MobSF"),
    Module("bugreport", X.collect_bugreport, 2, "full adb bugreport with artifact inventory/hashes"),
    Module("correlation", correlate.collect_correlation, 0, "package<->UID<->process<->socket correlation"),
]
NEEDS_PACKAGES = {"packages", "app_security", "network", "runtime", "apk_extract", "apk_analysis", "correlation", "services"}
NAMES = [m.name for m in REGISTRY]


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="adb_report.py", description="Read-only Android deep-enumeration over ADB (v%s)." % __version__)
    g = ap.add_argument_group("device / output")
    g.add_argument("-s", "--serial"); g.add_argument("--adb", default="adb", help="path to adb (default: next to script, then PATH)")
    g.add_argument("-o", "--output", help="Markdown report path (default: <out-dir>/report.md)")
    g.add_argument("--out-dir", help="artifact directory (default: adb_report_<model>_<timestamp>/)")
    g.add_argument("--json", metavar="PATH", help="JSON export path (default: <out-dir>/report.json)")
    g.add_argument("--baseline", metavar="JSON", help="previous report.json to diff against")
    g = ap.add_argument_group("profile / modules")
    g.add_argument("--profile", choices=list(LEVELS), default="deep", help="quick | deep (default) | exhaustive")
    g.add_argument("--modules", type=lambda s: [x for x in s.split(",") if x], help="comma list; run only these modules")
    g.add_argument("--skip-modules", type=lambda s: [x for x in s.split(",") if x], default=[], help="comma list of modules to skip")
    g.add_argument("--list-modules", action="store_true")
    g.add_argument("--users", help="current | all | comma list of user ids (default: current for quick, all otherwise)")
    g = ap.add_argument_group("timing")
    g.add_argument("--timeout", type=int, default=30, help="per-command timeout (s)")
    g.add_argument("--long-timeout", type=int, default=300, help="timeout for heavy dumps (s)")
    g.add_argument("--service-timeout", type=int, default=90, help="per-service dumpsys timeout (s)")
    g.add_argument("--retries", type=int, default=1); g.add_argument("--retry-delay", type=float, default=1.0)
    g = ap.add_argument_group("applications")
    g.add_argument("--skip-details", action="store_true", help="skip `dumpsys package` (fast; no versions/perms/flags)")
    g.add_argument("--hash-apps", action="store_true", help="device-side SHA-256 of APKs")
    g.add_argument("--hash-scope", choices=["auto", "third", "all"], default="auto")
    g.add_argument("--full-perms", action="store_true")
    g.add_argument("--pull-apks", nargs="?", const="", default=None, metavar="DIR", help="pull APKs (default dir: <out-dir>/apks)")
    g.add_argument("--apk-scope", default="third", help="third | all | comma list of packages")
    g.add_argument("--analyze-apks", action="store_true", help="pull APKs and run host-side tools")
    for t in ("apksigner", "apkanalyzer", "apktool", "jadx"):
        g.add_argument(f"--{t}", help=f"path to {t}")
    g.add_argument("--apktool-decode", action="store_true"); g.add_argument("--jadx-decompile", action="store_true", help="decompile with JADX and scan for URLs")
    g.add_argument("--mobsf-url"); g.add_argument("--mobsf-key"); g.add_argument("--tool-timeout", type=int, default=300)
    g = ap.add_argument_group("logs / bugreport / storage")
    g.add_argument("--logs", action="store_true", help="enable the logs module (crash buffer only on quick)")
    g.add_argument("--log-lines", type=int, help="lines per buffer (default 5000 deep, full on exhaustive)")
    g.add_argument("--log-buffers", help="comma list, e.g. main,system,crash")
    g.add_argument("--bugreport", action="store_true"); g.add_argument("--bugreport-timeout", type=int, default=1200)
    g.add_argument("--storage-index", nargs="*", default=None, metavar="ROOT", help="enable shared-storage indexing (optional roots)")
    g.add_argument("--storage-depth", type=int, default=0, help="0 = unlimited"); g.add_argument("--storage-max-entries", type=int, default=200000)
    g.add_argument("--storage-hash", action="store_true"); g.add_argument("--storage-hash-max-mb", type=int, default=50)
    g.add_argument("--storage-hash-max-files", type=int, default=5000)
    g = ap.add_argument_group("misc")
    g.add_argument("-v", "--verbose", action="store_true"); g.add_argument("-q", "--quiet", action="store_true")
    g.add_argument("--redact", action="store_true", help=argparse.SUPPRESS)
    g.add_argument("--version", action="version", version=f"adb_report.py {__version__}")
    return ap


def select_modules(args: argparse.Namespace) -> tuple[list[str], set[str]]:
    level = LEVELS[args.profile]
    explicit: set[str] = set()
    if args.modules:
        chosen = set(args.modules)
        explicit = set(chosen)
    else:
        chosen = {m.name for m in REGISTRY if m.level <= level}
    extras = []
    if args.logs: extras.append("logs")
    if args.pull_apks is not None: extras.append("apk_extract")
    if args.analyze_apks: extras += ["apk_extract", "apk_analysis"]
    if args.bugreport: extras.append("bugreport")
    if args.storage_index is not None: extras.append("storage_index")
    for e in extras:
        chosen.add(e)
        explicit.add(e)
    chosen -= set(args.skip_modules)
    unknown = (chosen | set(args.skip_modules)) - set(NAMES)
    if unknown:
        raise SystemExit(f"Unknown module(s): {', '.join(sorted(unknown))}. Use --list-modules.")
    return [m.name for m in REGISTRY if m.name in chosen], explicit


def run_collection(adb: Adb, args: argparse.Namespace, out_dir: Path, echo: Callable[[str], None] = lambda m: None) -> tuple[Ctx, dict]:
    t0 = time.monotonic()
    gp = adb.shell("getprop", label="getprop", timeout=60)
    props = P.parse_getprop(gp.stdout)
    if not props:
        raise AdbError("getprop returned nothing - is the device authorised and responsive?")
    ctx = Ctx(adb, args, props)
    ctx.out_dir = out_dir
    ctx.data["getprop_cmd"] = gp.id
    ctx.progress = lambda m: echo(f"    - {m}")
    capabilities.discover(ctx)
    D.collect_settings(ctx)
    D.prepare_users(ctx)
    modules, explicit = select_modules(args)
    base_level = ctx.level
    if any(n in NEEDS_PACKAGES for n in modules):
        echo("[*] Preparing package inventory ...")
        try:
            A.prepare_packages(ctx)
        except Exception as e:
            ctx.warnings.append(f"package preparation ({type(e).__name__}: {e})")
    reg = {m.name: m for m in REGISTRY}
    for i, name in enumerate(modules, 1):
        m = reg[name]
        echo(f"[{i}/{len(modules)} {100 * i // len(modules)}%] {name} - {m.doc} (t+{time.monotonic() - t0:.0f}s, {len(adb.log)} cmds)")
        ctx.level = max(base_level, m.level) if name in explicit else base_level
        try:
            m.fn(ctx)
            ctx.module_status[name] = "ok"
        except Exception as e:  # keep the report going
            ctx.module_status[name] = f"failed: {type(e).__name__}: {e}"
            ctx.warnings.append(f"{name} ({type(e).__name__}: {e})")
            ctx.add(name, f"_Collector failed: {type(e).__name__}: {e}_")
            echo(f"[!] {name} failed: {e}")
    ctx.level = base_level
    for name in NAMES:
        ctx.module_status.setdefault(name, "skipped (not selected)")
    findings.run_rules(ctx)
    meta = {"generated": dt.datetime.now().astimezone().isoformat(timespec="seconds"), "profile": args.profile, "modules_run": modules,
            "serial": adb.serial or "n/a"}
    if args.baseline:
        try:
            old = json.loads(Path(args.baseline).read_text(encoding="utf-8"))
            new = report.build_json(ctx, meta)
            diff = correlate.compare_baseline(old, json.loads(json.dumps(new, default=report._default)))
            ctx.data["baseline_diff"] = diff
            ctx.add("Baseline comparison", correlate.render_baseline(diff, args.baseline))
        except (OSError, ValueError) as e:
            ctx.warnings.append(f"baseline ({type(e).__name__}: {e})")
    return ctx, meta


def main(argv: Optional[list[str]] = None) -> int:
    for s in (sys.stdout, sys.stderr):
        try:
            s.reconfigure(encoding="utf-8", errors="replace")  # PowerShell/cmd code pages
        except (AttributeError, ValueError):
            pass
    args = build_parser().parse_args(argv)
    if args.list_modules:
        for m in REGISTRY:
            print(f"{m.name:14} min-profile={['quick', 'deep', 'exhaustive'][m.level]:10} {m.doc}")
        return 0
    echo = (lambda m: None) if args.quiet else (lambda m: print(m, file=sys.stderr, flush=True))
    if args.redact:
        echo("[!] --redact was removed in v3 (full-fidelity collection); the flag is ignored.")
    args.storage_roots = args.storage_index or []
    adb_bin = find_adb(args.adb)
    if not adb_bin:
        echo("[!] adb not found. Put adb(.exe) next to this script, add it to PATH, or pass --adb <path>.")
        return 2
    echo(f"[*] Using adb: {adb_bin}")
    try:
        serial = pick_device(adb_bin, args.serial)
    except AdbError as e:
        echo(f"[!] {e}")
        return 1
    echo(f"[*] Using device {serial}")
    stamp = dt.datetime.now().strftime("%Y%m%dT%H%M%S")
    tmp_model = safe_filename(args.serial or "device", 20)
    out_dir = Path(args.out_dir) if args.out_dir else Path(f"adb_report_{tmp_model}_{stamp}")
    adb = Adb(adb_bin, serial, args.timeout, args.retries, args.retry_delay, raw_dir=out_dir / "raw",
              echo=(echo if args.verbose else None))
    try:
        ctx, meta = run_collection(adb, args, out_dir, echo)
    except AdbError as e:
        echo(f"[!] {e}")
        return 1
    md = Path(args.output) if args.output else out_dir / "report.md"
    js = Path(args.json) if args.json else out_dir / "report.json"
    report.write_outputs(ctx, meta, out_dir, md, js)
    report.write_manifest(out_dir, meta)
    s = adb.summary()
    echo(f"[+] Report: {md.resolve()}\n[+] JSON: {js.resolve()}\n[+] Artifacts + manifest: {out_dir.resolve()}\n"
         f"[+] {s['total']} commands ({', '.join(f'{k} {v}' for k, v in s.items() if k != 'total' and v)}); {len(ctx.findings)} finding(s)")
    return 0
