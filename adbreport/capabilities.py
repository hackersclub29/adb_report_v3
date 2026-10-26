"""Runtime capability discovery: what the connected device, its shell and ADB transport can actually do."""
from __future__ import annotations

from .model import Ctx
from .parsers import parse_service_list, parse_getprop
from .adb import OK

PROBE_TOOLS = ["ip", "ss", "netstat", "ifconfig", "ps", "toybox", "sha256sum", "sha1sum", "md5sum", "openssl", "find",
               "stat", "ls", "cat", "df", "mount", "getenforce", "logcat", "dmesg", "settings", "pm", "cmd", "am", "wm",
               "dumpsys", "content", "sm", "bugreportz", "getprop", "uname", "id", "date", "iptables", "ime", "service",
               "appops", "zcat", "gzip", "head", "wc", "du", "ping"]


def discover(ctx: Ctx) -> None:
    adb = ctx.adb
    ctx.progress("capability discovery")
    ctx.caps["adb_features"] = adb.run(["features"], label="adb-features").text.split()
    ctx.caps["adb_version"] = (adb.run(["version"], label="adb-version").text.splitlines() or ["unknown"])[0]
    probe = ('for t in ' + " ".join(PROBE_TOOLS) +
             '; do if command -v $t >/dev/null 2>&1; then echo "$t=1"; else echo "$t=0"; fi; done')
    r = adb.shell(probe, label="tool-probe")
    tools = {}
    for ln in r.stdout.splitlines():
        k, _, v = ln.partition("=")
        if v in ("0", "1"):
            tools[k.strip()] = v == "1"
    if r.status == OK and tools.get("getprop") is not None:
        ctx.caps["tools"] = tools
    ctx.caps["stat_c"] = adb.shell("stat -c '%s' /system/bin/sh", label="probe-stat").status == OK
    ctx.caps["shell_identity"] = adb.text("id", label="shell-id")
    ctx.caps["sdk"] = ctx.sdk
    # services: dumpsys -> service list -> cmd -l
    names = parse_service_list(adb.text("dumpsys -l", label="dumpsys-list", timeout=60))
    ctx.caps["dumpsys_services"] = names
    binder = parse_service_list(adb.text("service list", label="service-list", timeout=60))
    ctx.caps["binder_services"] = binder
    ctx.caps["cmd_services"] = parse_service_list(adb.text("cmd -l", label="cmd-list", timeout=60))
    ctx.caps["services"] = sorted(set(names) | set(binder))
    # which logcat formats work is decided lazily by the logs collector
