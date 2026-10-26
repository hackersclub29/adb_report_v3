"""Markdown / JSON / manifest rendering."""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import platform
from collections import Counter, defaultdict
from pathlib import Path

from . import __version__, SCHEMA_VERSION
from .adb import STATUSES
from .model import Ctx, SEVERITIES, table, details, fence

LIMITS = [
    "IMEI / IMSI / ICCID / phone number: blocked from the adb shell on modern Android (privileged-permission gated); not collected.",
    "Other apps' private data (`/data/data`), saved Wi-Fi passwords and keystore material: protected by the Android sandbox without root; not collected.",
    "Non-exported/non-filtered component lists and signing certificates are only partially available on-device; use `--pull-apks --analyze-apks` for manifest/signature depth.",
    "Encrypted traffic content and historical network usage beyond what netstats retains: not visible.",
    "`/proc/kmsg`, `/data/anr`, `/data/tombstones`, `/data/misc/*` are normally unreadable to the shell user; crash/ANR history is taken from logcat, DropBox and `dumpsys activity exit-info` instead.",
    "Findings are evidence-based indicators, not proof of compromise; heuristic statements are labelled as such.",
]
REASON = {"denied": "Blocked by Android permissions / SELinux for the shell user.", "unsupported": "Command, service, option or path does not exist on this device/OS build.",
          "timeout": "Did not finish within the configured timeout.", "failed": "Non-zero exit or error output not matching denied/unsupported.",
          "blocked": "Refused by the tool's read-only guard (never sent to the device).", "empty": "Ran successfully but produced no output."}


def render_markdown(ctx: Ctx, meta: dict) -> str:
    inv = ctx.adb.summary()
    out = [f"# Android device report - {ctx.props.get('ro.product.model', 'Android device')}", "",
           f"- **Generated:** {meta['generated']}", f"- **Tool:** adb_report.py v{__version__} (read-only on the device)",
           f"- **Profile:** {meta['profile']}  |  **Modules run:** {', '.join(meta['modules_run'])}",
           f"- **ADB:** {ctx.caps.get('adb_version', 'unknown')}  |  **Host:** {platform.system()} {platform.release()}",
           f"- **Device serial:** {meta['serial']}  |  **Shell identity:** {ctx.caps.get('shell_identity', 'n/a')}",
           f"- **Commands:** {inv['total']} total - " + ", ".join(f"{s} {inv[s]}" for s in STATUSES if inv.get(s)), ""]
    fs = sorted(ctx.findings, key=lambda f: (SEVERITIES.index(f.severity), f.id))
    out += ["## Findings", "", "_Evidence-based indicators. **Observed** = read directly from the device. **Heuristic** = an inference drawn from those observations; verify before acting._", ""]
    if fs:
        out.append(table(["ID", "Severity", "Confidence", "Kind", "Finding"], [[f.id, f.severity, f.confidence, f.kind, f.title] for f in fs]))
        for f in fs:
            body = "**Observed facts**\n" + "\n".join(f"- {o}" for o in f.observations or ["-"])
            if f.heuristics:
                body += "\n\n**Heuristic interpretation (not a fact)**\n" + "\n".join(f"- {h}" for h in f.heuristics)
            if f.evidence:
                body += "\n\n**Evidence:** " + ", ".join(f"`{e}`" for e in f.evidence)
            if f.recommendation:
                body += f"\n\n**Suggested action:** {f.recommendation}"
            out += ["", details(f"{f.id} [{f.severity}/{f.confidence}] {f.title}", body)]
    else:
        out.append("- Nothing flagged by the built-in checks.")
    out.append("")
    cov = table(["Module", "Status"], [[k, v] for k, v in ctx.module_status.items()])
    out += ["## Module coverage", "", cov, ""]
    for title, body in ctx.sections:
        out += [f"## {title}", "", body, ""]
    out += ["## Command inventory", "", "Every device command issued, by outcome. Full machine-readable list: `commands.json`.", "",
            table(["Status", "Meaning", "Count"], [[s, REASON.get(s, "Succeeded (output captured; * = partial output despite non-zero exit)" if s == "ok" else ""), inv.get(s, 0)] for s in STATUSES])]
    groups: dict[str, list[dict]] = defaultdict(list)
    for m in ctx.adb.log:
        groups[m["status"]].append(m)
    for s in STATUSES:
        if s == "ok" or not groups.get(s):
            continue
        out += ["", details(f"{s} ({len(groups[s])})", table(["Id", "Command", "Exit", "stderr (head)"], [[m["id"], m["cmd"][:110], m["exit_code"], m["stderr_head"][:80]] for m in groups[s]]))]
    ok = groups.get("ok", [])
    out += ["", details(f"ok ({len(ok)})", table(["Id", "Command", "Partial", "Bytes", "Seconds"], [[m["id"], m["cmd"][:100], "yes" if m["partial"] else "", m["stdout_bytes"], m["duration_s"]] for m in ok]))]
    diags = ctx.data.get("parser_diagnostics", [])
    out += ["", "## Parser diagnostics", "", table(["Where", "Message"], [[d["where"], d["message"]] for d in diags]) if diags else "_No parser errors._"]
    if ctx.warnings:
        out += ["", "**Collector failures:** " + "; ".join(ctx.warnings)]
    out += ["", "## What was not collected, and why", ""]
    nonok = Counter(m["status"] for m in ctx.adb.log if m["status"] in ("denied", "unsupported", "timeout", "failed", "blocked"))
    out += [f"- **{s}** ({n} commands): {REASON[s]}" for s, n in nonok.items()] + [f"- {x}" for x in LIMITS]
    return "\n".join(out) + "\n"


def build_json(ctx: Ctx, meta: dict) -> dict:
    return {"schema_version": SCHEMA_VERSION, "tool": f"adb_report.py v{__version__}", "generated": meta["generated"], "serial": meta["serial"],
            "profile": meta["profile"], "modules_run": meta["modules_run"], "module_status": ctx.module_status,
            "capabilities": ctx.caps, "properties": ctx.props, "settings": ctx.settings, "findings": [{**f.__dict__, "kind": f.kind} for f in ctx.findings],
            "command_summary": ctx.adb.summary(), **{k: v for k, v in ctx.data.items() if k not in ("props", "settings")}, "props": ctx.props}


def _default(o):
    return sorted(o) if isinstance(o, (set, frozenset)) else str(o)


def write_outputs(ctx: Ctx, meta: dict, out_dir: Path, md_path: Path, json_path: Path) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    md_path.parent.mkdir(parents=True, exist_ok=True)
    md_path.write_text(render_markdown(ctx, meta), encoding="utf-8", newline="\n")
    json_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps(build_json(ctx, meta), indent=1, default=_default), encoding="utf-8", newline="\n")
    cmds = out_dir / "commands.json"
    cmds.write_text(json.dumps({"summary": ctx.adb.summary(), "commands": ctx.adb.log}, indent=1), encoding="utf-8", newline="\n")
    return [md_path, json_path, cmds]


def write_manifest(out_dir: Path, meta: dict) -> Path:
    arts = []
    for p in sorted(out_dir.rglob("*")):
        if p.is_file() and p.name != "manifest.json":
            h = hashlib.sha256()
            with p.open("rb") as fh:
                for chunk in iter(lambda: fh.read(1 << 20), b""):
                    h.update(chunk)
            st = p.stat()
            arts.append({"path": p.relative_to(out_dir).as_posix(), "bytes": st.st_size, "sha256": h.hexdigest(),
                         "modified_utc": dt.datetime.fromtimestamp(st.st_mtime, dt.timezone.utc).isoformat(timespec="seconds")})
    m = out_dir / "manifest.json"
    m.write_text(json.dumps({"tool": f"adb_report.py v{__version__}", "generated": meta["generated"], "serial": meta["serial"],
                             "profile": meta["profile"], "artifacts": arts}, indent=1), encoding="utf-8", newline="\n")
    return m
