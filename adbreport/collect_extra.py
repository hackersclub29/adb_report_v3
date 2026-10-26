"""Logs, kernel diagnostics, shared-storage indexing and bugreport collection."""
from __future__ import annotations

import csv
import datetime as dt
import hashlib
import posixpath
import re
import shlex
import zipfile
from collections import Counter
from pathlib import Path

from . import parsers as P
from .adb import OK
from .model import Ctx, Spec, table, fence, details, or_na, fmt_bytes

LOG_FORMATS = ["-v threadtime -v year -v UTC", "-v threadtime -v year", "-v threadtime", ""]
DEFAULT_BUFFERS_DEEP = ["main", "system", "crash", "events", "radio"]
BUF_RE = re.compile(r"^\w+$")


def collect_logs(ctx: Ctx) -> None:
    adb, args = ctx.adb, ctx.args
    sizes = adb.shell("logcat -g", label="logcat-buffer-sizes")
    avail = P.parse_logcat_buffers(sizes.stdout) if sizes.ok else []
    if args.log_buffers:
        want = [b for b in args.log_buffers.split(",") if BUF_RE.match(b)]
    elif ctx.level >= 2:
        want = avail or ["main", "system", "crash", "events", "radio", "kernel", "security", "stats"]
    elif ctx.level == 1:
        want = [b for b in DEFAULT_BUFFERS_DEEP if not avail or b in avail]
    else:
        want = ["crash"]
    limit = args.log_lines if args.log_lines is not None else (None if ctx.level >= 2 else 5000)
    t_arg = f" -t {int(limit)}" if limit else ""
    fmt = None
    summaries, crashes, events, samples = {}, [], {}, []
    for buf in want:
        ctx.progress(f"logcat -b {buf}")
        r = None
        for f in ([fmt] if fmt is not None else LOG_FORMATS):
            r = adb.shell(f"logcat -b {buf} -d{t_arg} {f}".strip(), label=f"logcat-{buf}", timeout=args.long_timeout, retries=0)
            if r.ok:
                fmt = f
                break
        entries, bad = P.parse_logcat(r.stdout) if r and r.ok else ([], 0)
        s = P.summarize_log(entries)
        s.update({"status": r.status if r else "n/a", "cmd_id": r.id if r else None, "unparsed_lines": bad, "bytes": len(r.stdout) if r else 0})
        summaries[buf] = s
        if buf == "events":
            events = P.parse_event_log(entries)
        if buf in ("crash", "main"):
            for i, e in enumerate(entries):
                if e["tag"] == "AndroidRuntime" and "FATAL EXCEPTION" in e["msg"]:
                    proc = None
                    for nxt in entries[i:i + 6]:  # the "Process:" line is a separate log entry from the same pid
                        m = re.search(r"Process: ([\w.:]+), PID: (\d+)", nxt["msg"])
                        if m and nxt["pid"] == e["pid"]:
                            proc = m.group(1)
                            break
                    crashes.append({"ts": e["ts"], "buffer": buf, "process": proc, "pid": e["pid"], "head": e["msg"].splitlines()[0][:120]})
        if buf in ("main", "system"):
            samples += [{k: e[k] for k in ("ts", "pid", "tid", "lvl", "tag")} | {"msg": e["msg"][:200]} for e in entries if e["lvl"] in ("E", "F")][:60]
    specs = [Spec("dmesg", "dmesg", ["dmesg"], 1, show=40, timeout=30), Spec("kernel_buf", "logcat -b kernel", ["logcat -b kernel -d"], 1, show=40, timeout=60),
             Spec("last_kmsg", "/proc/last_kmsg", ["cat /proc/last_kmsg"], 2, show=20), Spec("pstore", "pstore entries", ["ls -l /sys/fs/pstore"], 1, show=10),
             Spec("logcat_stats", "logcat statistics", ["logcat -S"], 2, show=30)]
    items = ctx.run_specs(specs)
    body = f"Format used: `{fmt or 'default'}`; line limit: `{limit or 'full buffer'}`. Timestamps are device-local as printed by logcat.\n\n"
    body += table(["Buffer", "Status", "Entries", "First", "Last", "E+F", "Unparsed lines"], [
        [b, s["status"], s["entries"], s["first"] or "", s["last"] or "", s["levels"].get("E", 0) + s["levels"].get("F", 0), s["unparsed_lines"]] for b, s in summaries.items()])
    for b, s in summaries.items():
        if s["entries"]:
            body += f"\n\n**Top tags in `{b}`**: " + ", ".join(f"{t} ({n})" for t, n in s["top_tags"][:8])
    if crashes:
        body += "\n\n**Java crashes (FATAL EXCEPTION)**\n\n" + table(["Time", "Buffer", "Process", "PID"], [[c["ts"], c["buffer"], c["process"], c["pid"]] for c in crashes[:50]])
    if events:
        body += "\n\n**Event log highlights**\n\n" + table(["Event", "Count"], [[k, len(v)] for k, v in events.items()])
    body += "\n\n" + ctx.render_items(items, specs)
    body += "\n\n_Full log buffers are preserved in `raw/`._"
    ctx.data["logs"] = {"format": fmt, "limit": limit, "buffers": summaries, "crashes": crashes, "events": {k: v[:100] for k, v in events.items()},
                        "error_samples": samples[:100]}
    ctx.add("Logs and diagnostics", body)


# ---------------------------------------------------------------- shared storage
def _q(p: str) -> str:
    return shlex.quote(p)


def _index_with_stat(ctx: Ctx, path: str, depth: int, budget: int, mindepth: int = 0) -> tuple[list[dict], list[str], str]:
    cmd = (f"find {_q(path)} -mindepth {mindepth} -maxdepth {depth} -exec stat -c '%F|%s|%Y|%A|%U|%n' {{}} + 2>&1 | head -n {budget}")
    r = ctx.adb.shell(cmd, label=f"storage-index-{posixpath.basename(path.rstrip('/')) or 'root'}", timeout=ctx.args.long_timeout, retries=0)
    return P.parse_stat_lines(r.stdout), P.parse_denied_paths(r.stdout), r.status


def _index_with_ls(ctx: Ctx, root: str, maxdepth: int, budget: int) -> tuple[list[dict], list[str], str]:
    rows, denied, queue, seen = [], [], [(root, 1)], 0
    status = "ok"
    while queue and len(rows) < budget and seen < 2000:
        d, depth = queue.pop(0)
        seen += 1
        r = ctx.adb.shell(f"ls -lA {_q(d)}", label="storage-ls", timeout=60, retries=0)
        if r.status in ("denied",) or (r.rc != 0 and not r.stdout.strip()):
            denied.append(d)
            continue
        for e in P.parse_ls_long(r.stdout, d):
            rows.append(e)
            if e["type"] == "dir" and depth < maxdepth:
                queue.append((e["path"], depth + 1))
    return rows, denied, status


def collect_storage_index(ctx: Ctx) -> None:
    adb, args = ctx.adb, ctx.args
    roots = list(args.storage_roots) if args.storage_roots else ["/sdcard"]
    if not args.storage_roots:
        for name in adb.text("ls /storage", label="storage-volumes").split():
            if name not in ("emulated", "self") and re.match(r"^[\w-]+$", name):
                roots.append(f"/storage/{name}")
    depth = args.storage_depth if args.storage_depth and args.storage_depth > 0 else 64
    budget = args.storage_max_entries
    use_stat = bool(ctx.caps.get("stat_c"))
    all_rows: list[dict] = []
    root_info, denied_all = [], []
    for root in roots:
        ctx.progress(f"indexing {root}")
        exists = adb.shell(f"ls -d {_q(root)}", label="storage-root-check")
        if not exists.ok:
            root_info.append({"root": root, "status": exists.status, "entries": 0, "note": "root not accessible; nothing collected"})
            continue
        rows, denied, status = [], [], "ok"
        if use_stat:
            top, den, st = _index_with_stat(ctx, root, 1, budget)
            rows += top
            denied += den
            for d in [t["path"] for t in top if t["type"] == "dir" and t["path"].rstrip("/") != root.rstrip("/")]:
                if len(all_rows) + len(rows) >= budget:
                    status = "truncated"
                    break
                sub, den, st = _index_with_stat(ctx, d, depth - 1, budget - len(all_rows) - len(rows), mindepth=1)
                rows += sub
                denied += den
                if st not in ("ok", "empty"):
                    denied.append(f"{d} (listing status: {st})") if st != "timeout" else denied.append(f"{d} (timed out; partial)")
        else:
            rows, denied, status = _index_with_ls(ctx, root, depth, budget)
        all_rows += rows
        denied_all += denied
        root_info.append({"root": root, "status": status, "entries": len(rows), "access_denied": sorted(set(denied))})
    # de-duplicate (a dir can appear in both passes)
    uniq = {r["path"]: r for r in all_rows}
    rows = list(uniq.values())[:budget]
    # optional hashing
    hashed = 0
    if args.storage_hash:
        cap = args.storage_hash_max_mb * 1024 * 1024
        files = [r for r in rows if r["type"] == "file"]
        todo = [r for r in files if r["size"] <= cap][:args.storage_hash_max_files]
        for r in files:
            r["sha256"], r["hash_status"] = None, "not-attempted"
        for r in files:
            if r["size"] > cap:
                r["hash_status"] = f"skipped: larger than {args.storage_hash_max_mb} MB"
        for i in range(0, len(todo), 20):
            part = todo[i:i + 20]
            res = adb.shell("sha256sum " + " ".join(_q(r["path"]) for r in part), label="storage-hash", timeout=args.long_timeout, retries=0)
            got = P.parse_sha_lines(res.stdout)
            for r in part:
                if r["path"] in got:
                    r["sha256"], r["hash_status"] = got[r["path"]], "ok"
                    hashed += 1
                else:
                    r["hash_status"] = "unreadable or tool unavailable"
        for r in files[args.storage_hash_max_files:]:
            if r["hash_status"] == "not-attempted":
                r["hash_status"] = "skipped: --storage-hash-max-files reached"
    # artifact
    out = Path(ctx.out_dir) if ctx.out_dir else None
    csv_rel = None
    if out:
        out.mkdir(parents=True, exist_ok=True)
        with (out / "storage_index.csv").open("w", encoding="utf-8", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(["path", "type", "size", "mtime_utc", "mode", "owner", "sha256", "hash_status"])
            for r in sorted(rows, key=lambda x: x["path"]):
                mt = dt.datetime.fromtimestamp(r["mtime"], dt.timezone.utc).isoformat() if isinstance(r.get("mtime"), int) else ""
                w.writerow([r["path"], r["type"], r["size"], mt, r.get("mode", ""), r.get("owner", ""), r.get("sha256") or "", r.get("hash_status", "")])
        csv_rel = "storage_index.csv"
    files = [r for r in rows if r["type"] == "file"]
    ext = Counter((posixpath.splitext(r["path"])[1].lower() or "(none)") for r in files)
    types = Counter(r["type"] for r in rows)
    body = table(["Root", "Status", "Entries", "Access-denied paths"], [[i["root"], i["status"], i["entries"], len(i.get("access_denied", []))] for i in root_info])
    body += "\n\n" + table(["Metric", "Value"], [["Entries indexed", len(rows)], ["Files / dirs / symlinks", f"{types['file']} / {types['dir']} / {types['symlink']}"],
                                               ["Total file bytes", fmt_bytes(sum(r["size"] for r in files))], ["Files hashed (SHA-256)", hashed],
                                               ["Depth limit", args.storage_depth or "unlimited"], ["Entry budget", budget], ["CSV artifact", csv_rel or "n/a"]])
    body += "\n\n**Top extensions**\n\n" + table(["Extension", "Files"], [[k, v] for k, v in ext.most_common(20)])
    body += "\n\n**Largest files**\n\n" + table(["Path", "Size"], [[r["path"], fmt_bytes(r["size"])] for r in sorted(files, key=lambda r: -r["size"])[:20]])
    den = sorted(set(denied_all))
    body += "\n\n" + details(f"Access-denied / unavailable paths ({len(den)}) - NOT collected", fence("\n".join(den) or "none"))
    if len(rows) >= budget:
        body += "\n\n_Entry budget reached; the index is truncated and must not be read as complete._"
    ctx.data["storage_index"] = {"roots": root_info, "entries": len(rows), "hashed": hashed, "csv": csv_rel, "access_denied": den,
                                 "extensions": dict(ext.most_common(50)), "truncated": len(rows) >= budget}
    ctx.add("Shared storage index", body)


# ---------------------------------------------------------------- bugreport
def _sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def collect_bugreport(ctx: Ctx) -> None:
    args = ctx.args
    out = Path(ctx.out_dir or ".") / "bugreport"
    out.mkdir(parents=True, exist_ok=True)
    ctx.progress("adb bugreport (can take several minutes)")
    before = {p.name for p in out.iterdir()}
    r = ctx.adb.run(["bugreport", str(out)], timeout=args.bugreport_timeout, label="bugreport", save=False, retries=0)
    new = [p for p in out.iterdir() if p.name not in before]
    info = {"status": r.status, "cmd_id": r.id, "files": []}
    body = f"`adb bugreport` status: **{r.status}** (`{r.id}`).\n\n"
    for f in new:
        entry = {"file": f"bugreport/{f.name}", "bytes": f.stat().st_size, "sha256": _sha256_file(f), "members": []}
        if zipfile.is_zipfile(f):
            with zipfile.ZipFile(f) as z:
                for zi in z.infolist():
                    h = hashlib.sha256()
                    with z.open(zi) as m:
                        for chunk in iter(lambda: m.read(1 << 20), b""):
                            h.update(chunk)
                    entry["members"].append({"name": zi.filename, "bytes": zi.file_size, "sha256": h.hexdigest()})
        info["files"].append(entry)
        body += f"**{entry['file']}** - {fmt_bytes(entry['bytes'])}, SHA-256 `{entry['sha256']}`\n\n"
        if entry["members"]:
            body += details(f"Archive inventory ({len(entry['members'])} members)", table(["Member", "Bytes", "SHA-256"], [[m["name"], m["bytes"], m["sha256"]] for m in entry["members"][:500]])) + "\n\n"
    if not new:
        body += "_No bugreport artifact was produced; see the command inventory for the reason (commonly: unsupported on this device, denied, or timed out)._"
    body += "\n\n_Note: the device's dumpstate service writes its own temporary archive on the device while generating a bugreport; no settings are changed._"
    ctx.data["bugreport"] = info
    ctx.add("Bugreport", body)
