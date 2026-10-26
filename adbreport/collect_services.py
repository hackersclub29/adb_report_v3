"""System-service diagnostics (dynamic service discovery) and runtime/process state."""
from __future__ import annotations

import re
from collections import Counter

from . import parsers as P
from .adb import OK
from .model import Ctx, Spec, table, fence, details, or_na, fmt_kb, fmt_bytes

SERVICE_NAME_RE = re.compile(r"^[\w.\-:@]+$")
# Services of interest, matched against what `dumpsys -l` actually reports on this device.
CURATED = ["activity", "alarm", "jobscheduler", "usagestats", "procstats", "batterystats", "battery", "power", "thermalservice",
           "deviceidle", "notification", "package", "permission", "permissionmgr", "appops", "role", "user", "connectivity",
           "netstats", "netpolicy", "network_management", "wifi", "wifiscanner", "wifip2p", "bluetooth_manager",
           "telephony.registry", "phone", "isub", "telecom", "usb", "location", "sensorservice", "display", "window", "input",
           "input_method", "accessibility", "autofill", "device_policy", "account", "content", "dropbox", "diskstats", "mount",
           "storaged", "dnsresolver", "vpn_management", "audio", "media_session", "trust", "restrictions", "overlay", "uimode",
           "companiondevice", "launcherapps", "shortcut", "cpuinfo", "gfxinfo", "SurfaceFlinger", "nfc", "carrier_config", "clipboard_placeholder"]
ACTIVITY_EXTRAS = ["processes", "services", "broadcasts", "providers", "recents", "exit-info", "lru", "intents", "top", "settings"]
DONE_ELSEWHERE = {"package", "meminfo", "SurfaceFlinger", "account", "device_policy", "battery", "sensorservice", "display", "mount",
                  "diskstats", "thermalservice", "accessibility", "role", "clipboard_placeholder"}
PARSE_NEEDED = {"alarm", "jobscheduler", "notification", "usagestats", "batterystats", "dropbox", "netstats", "activity exit-info",
                "bluetooth_manager", "wifi", "connectivity", "dnsresolver"}
DROPBOX_TAGS = ["data_app_crash", "data_app_anr", "system_app_crash", "system_app_anr", "system_server_crash", "system_server_anr",
                "system_server_wtf", "SYSTEM_TOMBSTONE", "data_app_native_crash", "system_app_native_crash"]


def collect_services(ctx: Ctx) -> None:
    adb, args = ctx.adb, ctx.args
    avail = ctx.caps.get("dumpsys_services") or []
    if ctx.level >= 2:
        names = [n for n in avail] or CURATED
    else:
        names = [n for n in CURATED if n in avail] if avail else CURATED
    names = [n for n in dict.fromkeys(names) if SERVICE_NAME_RE.match(n)]
    jobs: list[tuple[str, str]] = []
    for n in names:
        if n in DONE_ELSEWHERE:
            continue
        if n == "activity":
            jobs += [(f"activity {x}", f"dumpsys activity {x}") for x in ACTIVITY_EXTRAS]
        jobs.append((n, f"dumpsys {n}"))
    ctx.service_texts = {}
    rows, inventory = [], []
    for i, (name, cmd) in enumerate(jobs, 1):
        ctx.progress(f"dumpsys {name} ({i}/{len(jobs)})")
        r = adb.shell(cmd, label=f"dumpsys-{name}", timeout=args.service_timeout, retries=0)
        inventory.append({"service": name, "status": r.status, "lines": len(r.stdout.splitlines()), "bytes": len(r.stdout.encode("utf-8", "replace")), "cmd_id": r.id})
        if r.ok and name in PARSE_NEEDED:
            ctx.service_texts[name] = r.stdout
    if ctx.level >= 2 and "dropbox" in avail:
        for tag in DROPBOX_TAGS:
            adb.shell(f"dumpsys dropbox --print {tag}", label=f"dropbox-{tag}", timeout=args.service_timeout, retries=0)
    cnt = Counter(x["status"] for x in inventory)
    body = f"Discovered **{len(avail)}** dumpsys services on this device ({len(ctx.caps.get('binder_services', []))} binder services, " \
           f"{len(ctx.caps.get('cmd_services', []))} `cmd` services). Dumped **{len(inventory)}** (profile `{args.profile}`).\n\n"
    body += table(["Status", "Count"], [[k, v] for k, v in cnt.most_common()])
    body += "\n\n" + details("Service dump inventory", table(["Service", "Status", "Lines", "Bytes", "Cmd"], [
        [x["service"], x["status"], x["lines"], x["bytes"], x["cmd_id"]] for x in inventory]))
    body += "\n\n" + details(f"All discovered dumpsys services ({len(avail)})", fence("\n".join(avail) or "dumpsys -l unavailable"))
    body += "\n\n" + details("Binder services (`service list`)", fence("\n".join(ctx.caps.get("binder_services", [])) or "unavailable"))
    body += "\n\n" + details("`cmd` services", fence("\n".join(ctx.caps.get("cmd_services", [])) or "unavailable"))
    body += "\n\n_Full dumps are preserved in `raw/` (one file per command)._"
    ctx.data["services"] = {"dumpsys": avail, "binder": ctx.caps.get("binder_services", []), "cmd": ctx.caps.get("cmd_services", []), "dump_inventory": inventory}
    ctx.add("System services (dynamic discovery)", body)


def collect_runtime(ctx: Ctx) -> None:
    adb = ctx.adb
    specs = [
        Spec("ps", "Process list", ["ps -A -o USER,UID,PID,PPID,RSS,VSZ,S,NAME", "ps -A -o USER,PID,PPID,RSS,NAME", "ps -A", "ps"], 0, timeout=30, show=0),
        Spec("loadavg", "/proc/loadavg", ["cat /proc/loadavg"], 0, show=2),
        Spec("top", "top snapshot", ["top -b -n 1 -m 25", "top -n 1 -m 25"], 1, timeout=30, show=40),
        Spec("cpuinfo_dump", "dumpsys cpuinfo", ["dumpsys cpuinfo"], 1, timeout=60, show=30),
        Spec("procstats", "dumpsys procstats", ["dumpsys procstats --hours 24", "dumpsys procstats"], 2, timeout=90, show=0),
    ]
    items = {i.key: i for i in ctx.run_specs(specs)}
    ctx.procs = P.parse_ps(items["ps"].text)
    st = getattr(ctx, "service_texts", {})
    usage = P.parse_usagestats(st.get("usagestats", ""))
    exits = P.parse_exit_info(st.get("activity exit-info", ""))
    alarms, jobs, notifs = P.parse_alarms(st.get("alarm", "")), P.parse_jobs(st.get("jobscheduler", "")), P.parse_notifications(st.get("notification", ""))
    dropbox = P.parse_dropbox(st.get("dropbox", ""))
    power = P.parse_batterystats_power(st.get("batterystats", ""))
    body = ""
    procs = ctx.procs
    if procs:
        tp = [p for p in procs if p["name"].split(":")[0] in ctx.third]
        body += f"**Running third-party app processes ({len(tp)})**\n\n" + table(["Process", "PID", "User", "UID", "RSS"], [
            [p["name"], p["pid"], p["user"], p["uid"], fmt_kb(p["rss_kb"])] for p in sorted(tp, key=lambda p: -p["rss_kb"])])
        body += "\n\n**Processes by user**\n\n" + table(["User", "Count"], [[u, n] for u, n in Counter(p["user"] for p in procs).most_common(15)])
        body += "\n\n**Top 20 by RSS**\n\n" + table(["Process", "PID", "User", "RSS"], [[p["name"], p["pid"], p["user"], fmt_kb(p["rss_kb"])] for p in sorted(procs, key=lambda p: -p["rss_kb"])[:20]])
    body += "\n\n" + details(f"All processes ({len(procs)})", fence(items["ps"].text or "unavailable"))
    if usage:
        tpu = sorted(((p, v) for p, v in usage.items() if p in ctx.third), key=lambda kv: kv[1]["last_used"], reverse=True)[:40]
        body += "\n\n**Third-party apps by last use** (`dumpsys usagestats`)\n\n" + table(["Package", "Last used", "Total foreground"], [[p, v["last_used"], v["total_time"]] for p, v in tpu])
    if exits:
        c = Counter((e["process"] or "?", e["reason"] or "?") for e in exits)
        body += f"\n\n**Process-exit records** ({len(exits)}; `dumpsys activity exit-info`)\n\n" + table(["Process", "Reason", "Count"], [[a, b, n] for (a, b), n in c.most_common(40)])
    for title, d in (("Alarms by package", alarms), ("Scheduled jobs by package", jobs), ("Active notifications by package", notifs)):
        if d:
            body += f"\n\n**{title}**\n\n" + table(["Package", "Count"], [[k, v] for k, v in sorted(d.items(), key=lambda kv: -kv[1])[:30]])
    if dropbox:
        body += "\n\n**DropBox entries by tag** (crash/ANR/tombstone history)\n\n" + table(["Tag", "Entries"], [[k, v] for k, v in sorted(dropbox.items(), key=lambda kv: -kv[1])])
    if power:
        body += "\n\n" + details("Estimated power use by UID (`dumpsys batterystats`)", table(["UID", "mAh"], [[p["uid"], p["mah"]] for p in sorted(power, key=lambda x: -x["mah"])[:30]]))
    body += "\n\n" + ctx.render_items(list(items.values()), specs)
    ctx.data["runtime"] = {"processes": procs, "usage": usage, "exit_info": exits, "alarms_by_package": alarms, "jobs_by_package": jobs,
                           "notifications_by_package": notifs, "dropbox": dropbox, "power_by_uid": power}
    ctx.add("Runtime: processes, usage, alarms, jobs, exits", body)
