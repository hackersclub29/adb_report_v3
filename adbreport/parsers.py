"""Pure parsers (no device access). Every parser tolerates missing/odd input and returns empty structures."""
from __future__ import annotations

import ipaddress
import re
from collections import Counter, defaultdict
from typing import Any

PKG_RE = re.compile(r"^[\w.]+$")
COMP_RE = re.compile(r"([A-Za-z][\w.]*)/(\.?[\w.$]+)")
TCP_STATES = {"01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV", "04": "FIN_WAIT1", "05": "FIN_WAIT2",
              "06": "TIME_WAIT", "07": "CLOSE", "08": "CLOSE_WAIT", "09": "LAST_ACK", "0A": "LISTEN", "0B": "CLOSING"}
ARM_PARTS = {"0xd01": "Cortex-A32", "0xd03": "Cortex-A53", "0xd04": "Cortex-A35", "0xd05": "Cortex-A55",
             "0xd07": "Cortex-A57", "0xd08": "Cortex-A72", "0xd09": "Cortex-A73", "0xd0a": "Cortex-A75",
             "0xd0b": "Cortex-A76", "0xd0d": "Cortex-A77", "0xd41": "Cortex-A78", "0xd44": "Cortex-X1",
             "0xd46": "Cortex-A510", "0xd47": "Cortex-A710", "0xd48": "Cortex-X2", "0xd4d": "Cortex-A715",
             "0xd4e": "Cortex-X3", "0xd80": "Cortex-A520", "0xd81": "Cortex-A720", "0xd82": "Cortex-X4",
             "0xd85": "Cortex-X925", "0xd87": "Cortex-A725"}
FIXED_UIDS = {"root": 0, "daemon": 1, "system": 1000, "radio": 1001, "bluetooth": 1002, "graphics": 1003,
              "input": 1004, "audio": 1005, "camera": 1006, "log": 1007, "mount": 1009, "wifi": 1010, "adb": 1011,
              "install": 1012, "media": 1013, "dhcp": 1014, "sdcard_rw": 1015, "vpn": 1016, "keystore": 1017,
              "usb": 1018, "drm": 1019, "gps": 1021, "media_rw": 1023, "nfc": 1027, "shell": 2000, "cache": 2001,
              "diag": 2002, "net_bt_admin": 3001, "net_bt": 3002, "inet": 3003, "net_raw": 3004, "net_admin": 3005,
              "nobody": 9999}


def _int(v: Any, default: int = 0) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


# ------------------------------------------------------------------ props / generic
def parse_getprop(text: str) -> dict[str, str]:
    return {m.group(1): m.group(2) for m in re.finditer(r"^\[([^\]\n]+)\]: \[(.*?)\]$", text, re.M | re.S)}


def parse_kv_lines(text: str, sep: str = "=") -> dict[str, str]:
    out = {}
    for ln in text.splitlines():
        if sep in ln:
            k, _, v = ln.partition(sep)
            if k.strip():
                out[k.strip()] = v.strip()
    return out


def parse_colon_kv(text: str) -> dict[str, str]:
    """`dumpsys battery` style: 'level: 87'."""
    return {k.strip(): v.strip() for k, v in re.findall(r"^\s*([\w ./-]+?):\s*(.*?)\s*$", text, re.M)}


def parse_cmdline(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for tok in re.findall(r'(?:[^\s"]|"[^"]*")+', text.strip()):
        k, eq, v = tok.partition("=")
        out[k] = v.strip('"') if eq else ""
    return out


def parse_meminfo(text: str) -> dict[str, int]:
    return {m.group(1): int(m.group(2)) for m in re.finditer(r"^([\w()]+):\s+(\d+)\s*kB", text, re.M)}


def parse_psi(text: str) -> dict[str, dict[str, float]]:
    out: dict[str, dict[str, float]] = {}
    for ln in text.splitlines():
        p = ln.split()
        if p and p[0] in ("some", "full"):
            out[p[0]] = {k: float(v) for k, v in (x.split("=") for x in p[1:] if "=" in x)}
    return out


def parse_cpuinfo(text: str) -> dict:
    cores = len(re.findall(r"^processor\s*:", text, re.M))
    impl = re.findall(r"^CPU implementer\s*:\s*(0x[0-9a-fA-F]+)", text, re.M)
    part = re.findall(r"^CPU part\s*:\s*(0x[0-9a-fA-F]+)", text, re.M)
    micro = Counter(ARM_PARTS.get(p.lower(), f"{i}/{p}") if i.lower() == "0x41" else f"{i}/{p}"
                    for i, p in zip(impl, part))
    feat = re.search(r"^(?:Features|flags)\s*:\s*(.+)$", text, re.M)
    hw = re.search(r"^Hardware\s*:\s*(.+)$", text, re.M)
    model = re.search(r"^model name\s*:\s*(.+)$", text, re.M)
    return {"cores": cores, "microarchitectures": dict(micro), "features": sorted(set(feat.group(1).split())) if feat else [],
            "hardware": hw.group(1).strip() if hw else None, "model_name": model.group(1).strip() if model else None}


def parse_cpu_freq(text: str) -> list[dict]:
    rows = []
    for ln in text.splitlines():
        f = ln.split("|")
        if len(f) >= 2 and f[0].startswith("cpu"):
            rows.append({"cpu": f[0], "max_khz": _int(f[1], -1), "cur_khz": _int(f[2], -1) if len(f) > 2 else -1,
                         "min_khz": _int(f[3], -1) if len(f) > 3 else -1, "governor": f[4] if len(f) > 4 else ""})
    return rows


def parse_thermal_sysfs(text: str) -> list[dict]:
    rows = []
    for ln in text.splitlines():
        t, _, v = ln.partition("|")
        if v.strip().lstrip("-").isdigit():
            val = int(v)
            rows.append({"zone": t or "?", "temp_c": val / 1000 if abs(val) >= 1000 else float(val)})
    return rows


def parse_thermalservice(text: str) -> list[dict]:
    return [{"name": m.group(3), "type": _int(m.group(2)), "value_c": float(m.group(1))}
            for m in re.finditer(r"Temperature\{mValue=(-?[\d.]+), mType=(\d+), mName=([^,}]+)", text)]


def parse_dumpsys_meminfo(text: str) -> dict:
    out: dict[str, Any] = {}
    for key, pat in (("total_ram_kb", r"Total RAM:\s*([\d,]+)K"), ("free_ram_kb", r"Free RAM:\s*([\d,]+)K"),
                     ("used_ram_kb", r"Used RAM:\s*([\d,]+)K"), ("lost_ram_kb", r"Lost RAM:\s*([\d,]+)K")):
        m = re.search(pat, text)
        if m:
            out[key] = int(m.group(1).replace(",", ""))
    m = re.search(r"Total RAM:.*\(status (\w+)\)", text)
    if m:
        out["memory_status"] = m.group(1)
    sec = re.search(r"Total PSS by process:\n((?:[ \t]+.+\n?)+)", text)
    out["top_pss"] = [{"process": m.group(2), "pid": int(m.group(3)), "pss_kb": int(m.group(1).replace(",", ""))}
                      for m in re.finditer(r"^\s+([\d,]+)K: (\S+) \(pid (\d+)", sec.group(1), re.M)] if sec else []
    return out


def parse_sensors(text: str) -> list[dict]:
    seen, out = set(), []
    for m in re.finditer(r"^\s*0x[0-9a-fA-F]+\)\s+(.+?)\s*\|\s*(.+?)\s*\|\s*ver:\s*\d+\s*\|\s*type:\s*([\w.]+)", text, re.M):
        key = (m.group(1), m.group(3))
        if key not in seen:
            seen.add(key)
            out.append({"name": m.group(1), "vendor": m.group(2), "type": m.group(3).replace("android.sensor.", "")})
    return out


def parse_display(text: str) -> dict:
    modes = sorted({(int(w), int(h), float(f)) for w, h, f in re.findall(r"width=(\d+), height=(\d+), fps=([\d.]+)", text)})
    return {"modes": [{"width": w, "height": h, "fps": f} for w, h, f in modes],
            "refresh_rates": sorted({f for _, _, f in modes}),
            "hdr_types": sorted(set(re.findall(r"HdrCapabilities\{.*?supportedHdrTypes=\[([\d, ]*)\]", text)))}


def parse_battery(text: str) -> dict:
    kv = parse_colon_kv(text)
    status = {"1": "unknown", "2": "charging", "3": "discharging", "4": "not charging", "5": "full"}
    health = {"1": "unknown", "2": "good", "3": "overheat", "4": "dead", "5": "over voltage", "6": "failure", "7": "cold"}
    out: dict[str, Any] = dict(kv)
    out["status_text"] = status.get(kv.get("status", ""), kv.get("status"))
    out["health_text"] = health.get(kv.get("health", ""), kv.get("health"))
    if kv.get("temperature", "").lstrip("-").isdigit():
        out["temperature_c"] = int(kv["temperature"]) / 10
    out["power_sources"] = [k for k in ("AC powered", "USB powered", "Wireless powered", "Dock powered") if kv.get(k) == "true"]
    return out


# ------------------------------------------------------------------ storage
def parse_df(text: str) -> list[dict]:
    rows = []
    for ln in text.splitlines()[1:]:
        f = ln.split()
        if len(f) >= 6 and f[1].isdigit():
            rows.append({"filesystem": f[0], "size_kb": int(f[1]), "used_kb": _int(f[2]), "avail_kb": _int(f[3]),
                         "use_pct": f[4], "mount": " ".join(f[5:])})
    return rows


def parse_mounts(text: str) -> list[dict]:
    rows = []
    for ln in text.splitlines():
        f = ln.split()
        if len(f) >= 4:
            rows.append({"device": f[0], "mount": f[1], "fstype": f[2], "options": f[3]})
    return rows


def parse_partitions(text: str) -> list[dict]:
    return [{"major": int(m[0]), "minor": int(m[1]), "blocks_kb": int(m[2]), "name": m[3]}
            for m in re.findall(r"^\s*(\d+)\s+(\d+)\s+(\d+)\s+(\S+)\s*$", text, re.M)]


def parse_filesystems(text: str) -> list[dict]:
    return [{"nodev": ln.startswith("nodev"), "name": ln.split()[-1]} for ln in text.splitlines() if ln.strip()]


def parse_diskstats(text: str) -> dict:
    def arr(label: str) -> list[str]:
        m = re.search(rf"{label}: \[(.*?)\]", text)
        return [x.strip().strip('"') for x in m.group(1).split(",")] if m and m.group(1).strip() else []
    names, app, data, cache = arr("Package Names"), arr("App Sizes"), arr("App Data Sizes"), arr("Cache Sizes")
    apps = []
    for i, n in enumerate(names):
        apps.append({"package": n, "app_bytes": _int(app[i]) if i < len(app) else 0,
                     "data_bytes": _int(data[i]) if i < len(data) else 0,
                     "cache_bytes": _int(cache[i]) if i < len(cache) else 0})
    return {"apps": apps, "summary": dict(re.findall(r"^([A-Za-z\- ]+(?:Size|Free|Encryption)): (.+)$", text, re.M))}


_STAT = re.compile(r"^(?P<type>[^|]*)\|(?P<size>\d+)\|(?P<mtime>-?\d+)\|(?P<mode>[^|]*)\|(?P<user>[^|]*)\|(?P<path>.+)$")


def parse_stat_lines(text: str) -> list[dict]:
    """Lines from `stat -c '%F|%s|%Y|%A|%U|%n'`."""
    rows = []
    for ln in text.splitlines():
        m = _STAT.match(ln)
        if m:
            t = m["type"].lower()
            rows.append({"path": m["path"], "type": "dir" if "directory" in t else "symlink" if "link" in t else
                         "file" if "file" in t else t, "size": int(m["size"]), "mtime": int(m["mtime"]),
                         "mode": m["mode"], "owner": m["user"]})
    return rows


def parse_denied_paths(text: str) -> list[str]:
    out = []
    for ln in text.splitlines():
        m = re.match(r"^(?:find|ls|stat|sha256sum|cat):\s*'?(.+?)'?:\s*(Permission denied|Operation not permitted)", ln.strip())
        if m:
            out.append(m.group(1))
    return out


# ------------------------------------------------------------------ packages
_KVTOK = r"(?:\s+[\w.]+[:=]\S*)*"
_PM_NAME = re.compile(rf"^package:([\w.]+)({_KVTOK})\s*$")
_PM_PATH = re.compile(rf"^package:(?P<path>.+?)=(?P<pkg>[\w.]+)(?P<rest>{_KVTOK})\s*$")


def _kv(rest: str) -> dict[str, str]:
    return {k: v for k, v in re.findall(r"([\w.]+)[:=](\S*)", rest)}


def parse_pm_list(text: str) -> dict[str, dict]:
    apps: dict[str, dict] = {}
    for line in text.splitlines():
        line = line.strip()
        m = _PM_NAME.match(line)
        if m:
            kv = _kv(m.group(2))
            apps.setdefault(m.group(1), {"path": "", "installer": kv.get("installer"), "uid": kv.get("uid"),
                                         "version_code": kv.get("versionCode")})
            continue
        m = _PM_PATH.match(line)
        if m:
            kv = _kv(m["rest"])
            apps[m["pkg"]] = {"path": m["path"], "installer": kv.get("installer"), "uid": kv.get("uid"),
                              "version_code": kv.get("versionCode")}
    return apps


def parse_pm_names(text: str) -> set[str]:
    return set(re.findall(r"^package:([\w.]+)", text, re.M))


def parse_pm_path(text: str) -> list[str]:
    return [ln[8:].strip() for ln in text.splitlines() if ln.startswith("package:")]


def parse_pm_users(text: str) -> list[dict]:
    return [{"id": int(m.group(1)), "name": m.group(2), "flags": m.group(3), "running": "running" in m.group(4)}
            for m in re.finditer(r"UserInfo\{(\d+):([^:}]*):([0-9a-fA-F]+)\}(.*)", text)]


def parse_pm_features(text: str) -> list[str]:
    return [ln[8:].strip() for ln in text.splitlines() if ln.startswith("feature:")]


def parse_pm_libraries(text: str) -> list[str]:
    return [ln[8:].strip() for ln in text.splitlines() if ln.startswith("library:")]


def parse_permission_list(text: str) -> dict:
    groups: dict[str, dict] = {}
    perms: dict[str, dict] = {}
    cur_group, last = None, None
    for ln in text.splitlines():
        s = ln.strip().lstrip("+").strip()
        if s.startswith("group:"):
            cur_group = s[6:].strip()
            groups.setdefault(cur_group, {})
            last = ("g", cur_group)
        elif s.startswith("ungrouped:"):
            cur_group, last = None, None
        elif s.startswith("permission:"):
            n = s[11:].strip()
            perms[n] = {"group": cur_group}
            last = ("p", n)
        elif last and s.startswith("protectionLevel:"):
            (perms if last[0] == "p" else groups)[last[1]]["protection"] = s.split(":", 1)[1].strip()
        elif last and s.startswith("package:"):
            (perms if last[0] == "p" else groups)[last[1]]["package"] = s.split(":", 1)[1].strip()
        elif last and s.startswith("label:"):
            (perms if last[0] == "p" else groups)[last[1]]["label"] = s.split(":", 1)[1].strip()
    return {"groups": groups, "permissions": perms}


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


_PERM_HDR = {"requested permissions:", "install permissions:", "declared permissions:", "grantedPermissions:"}
_PKG_HDR = re.compile(r"^  Package \[([^\]]+)\]", re.M)


def parse_package_chunk(chunk: str) -> dict:
    def grab(p: str) -> str | None:
        m = re.search(p, chunk, re.M)
        return m.group(1).strip() if m else None

    lines = chunk.splitlines()
    requested: list[str] = []
    install: dict[str, bool] = {}
    declared: list[str] = []
    users: dict[int, dict] = {}
    runtime: dict[int, dict] = {}
    i = 0
    while i < len(lines):
        ln, ind, s = lines[i], _indent(lines[i]), lines[i].strip()
        if ind == 4 and s in _PERM_HDR:
            j = i + 1
            while j < len(lines) and (not lines[j].strip() or _indent(lines[j]) >= 6):
                item = lines[j].strip()
                if item:
                    name = item.split(":")[0].strip()
                    if s.startswith("requested"):
                        requested.append(name)
                    elif s.startswith("declared"):
                        declared.append(name)
                    else:
                        g = re.search(r"granted=(true|false)", item)
                        install[name] = (g.group(1) == "true") if g else True
                j += 1
            i = j
            continue
        mu = re.match(r"^User (\d+): (.*)$", s) if ind == 4 else None
        if mu:
            uid = int(mu.group(1))
            users[uid] = {k: v for k, v in re.findall(r"(\w+)=(\S+)", mu.group(2))}
            rt: dict[str, dict] = {}
            in_rt, j = False, i + 1
            while j < len(lines) and (not lines[j].strip() or _indent(lines[j]) >= 6):
                s2, i2 = lines[j].strip(), _indent(lines[j])
                if i2 == 6:
                    in_rt = s2.startswith("runtime permissions")
                elif in_rt:
                    mp = re.match(r"([\w.]+): granted=(true|false)(?:, flags=\[\s*(.*?)\s*\])?", s2)
                    if mp:
                        rt[mp.group(1)] = {"granted": mp.group(2) == "true",
                                           "flags": [f for f in (mp.group(3) or "").split("|") if f]}
                j += 1
            runtime[uid] = rt
            i = j
            continue
        i += 1
    granted = {p for p, g in install.items() if g}
    for rt in runtime.values():
        granted |= {p for p, v in rt.items() if v["granted"]}
    sig = re.search(r"signatures=PackageSignatures\{[0-9a-f]+ version:(\d+), signatures:\[([^\]]*)\], past signatures:\[([^\]]*)\]", chunk)
    if sig:
        signing = {"scheme_version": int(sig.group(1)), "hashes": [x.strip() for x in sig.group(2).split(",") if x.strip()],
                   "past_hashes": [x.strip() for x in sig.group(3).split(",") if x.strip()]}
    else:
        old = re.search(r"signatures=PackageSignatures\{[^}]*\[([0-9a-fA-F, ]*)\]\}", chunk)
        signing = {"scheme_version": None, "hashes": [x.strip() for x in old.group(1).split(",") if x.strip()] if old else [],
                   "past_hashes": []}
    splits = grab(r"splits=\[(.*?)\]")
    return {
        "version_name": grab(r"versionName=(\S+)"), "version_code": grab(r"versionCode=(\d+)"),
        "min_sdk": grab(r"minSdk=(\d+)"), "target_sdk": grab(r"targetSdk=(\d+)"), "user_id": grab(r"userId=(\d+)"),
        "shared_user": grab(r"sharedUser=(?:SharedUserSetting)?\{?[0-9a-f]* ?([\w.]+)"),
        "code_path": grab(r"codePath=(\S+)"), "resource_path": grab(r"resourcePath=(\S+)"),
        "native_lib_dir": grab(r"legacyNativeLibraryDir=(\S+)"), "data_dir": grab(r"dataDir=(\S+)"),
        "primary_abi": grab(r"primaryCpuAbi=(\S+)"), "secondary_abi": grab(r"secondaryCpuAbi=(\S+)"),
        "splits": [x.strip() for x in splits.split(",") if x.strip()] if splits else [],
        "apk_signing_version": grab(r"apkSigningVersion=(\d+)"),
        "first_install": grab(r"firstInstallTime=(.+)"), "last_update": grab(r"lastUpdateTime=(.+)"),
        "installer": grab(r"installerPackageName=(\S+)"), "installer_uid": grab(r"installerPackageUid=(-?\d+)"),
        "initiating_installer": grab(r"installInitiatingPackageName=(\S+)"),
        "originating_installer": grab(r"installOriginatingPackageName=(\S+)"),
        "flags": (grab(r"^\s+(?:pkgFlags|flags)=\[\s*(.*?)\s*\]") or "").split(),
        "private_flags": (grab(r"^\s+(?:privateFlags|privatePkgFlags)=\[\s*(.*?)\s*\]") or "").split(),
        "signing": signing, "requested_perms": requested, "declared_perms": declared,
        "install_perms": install, "runtime_perms": {str(k): v for k, v in runtime.items()},
        "granted": sorted(granted), "requested": len(requested),
        "users": {str(k): v for k, v in users.items()},
    }


def parse_dumpsys_packages(text: str) -> dict[str, dict]:
    start = text.find("\nPackages:\n")
    if start != -1:
        text = text[start:]
    ms = list(_PKG_HDR.finditer(text))
    out: dict[str, dict] = {}
    for i, m in enumerate(ms):
        end = ms[i + 1].start() if i + 1 < len(ms) else len(text)
        chunk = text[m.end():end]
        stop = re.search(r"^\S", chunk, re.M)
        if stop:
            chunk = chunk[:stop.start()]
        if m.group(1) not in out:
            out[m.group(1)] = parse_package_chunk(chunk)
    return out


def parse_resolver_tables(text: str) -> dict[str, dict[str, dict]]:
    """Components that declare intent filters, from `dumpsys package` resolver tables."""
    kinds = {"Activity Resolver Table:": "activity", "Receiver Resolver Table:": "receiver",
             "Service Resolver Table:": "service", "Provider Resolver Table:": "provider"}
    out: dict[str, dict[str, dict]] = {v: {} for v in kinds.values()}
    kind, comp = None, None
    for ln in text.splitlines():
        if ln and not ln.startswith(" "):
            kind, comp = kinds.get(ln.strip()), None
            continue
        if not kind:
            continue
        m = re.match(r"^\s+[0-9a-f]+ ([\w.]+/[\w.$]+) filter [0-9a-f]+", ln)
        if m:
            comp = out[kind].setdefault(m.group(1), {"actions": set(), "categories": set(), "schemes": set()})
            continue
        if comp is not None:
            for key, pat in (("actions", "Action"), ("categories", "Category"), ("schemes", "Scheme")):
                mm = re.match(rf'^\s+{pat}: "(.*)"', ln)
                if mm:
                    comp[key].add(mm.group(1))
    return out


def parse_provider_authorities(text: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = defaultdict(list)
    sec = re.search(r"ContentProvider Authorities:\n((?:[ \t]+.+\n?)+)", text)
    if sec:
        for m in re.finditer(r"^\s+\[(.+?)\]:\s*\n\s+Provider\{[0-9a-f]+ ([\w.]+)/", sec.group(1), re.M):
            out[m.group(2)].append(m.group(1))
    return dict(out)


def parse_appop_holders(text: str) -> list[str]:
    seen: list[str] = []
    for line in text.splitlines():
        tok = line.strip().rstrip(":")
        if "." in tok and PKG_RE.match(tok) and tok not in seen:
            seen.append(tok)
    return seen


def parse_appops_get(text: str) -> dict[str, str]:
    out = {}
    for m in re.finditer(r"^\s*(?:Uid mode:\s*)?([A-Z][A-Z0-9_]+)(?:\(\d+\))?:\s*(\w+)", text, re.M):
        out[m.group(1)] = m.group(2)
    return out


def parse_components(text: str) -> dict[str, set[str]]:
    comps: dict[str, set[str]] = defaultdict(set)
    for pkg, cls in COMP_RE.findall(text):
        comps[pkg].add(cls)
    return comps


def parse_roles(text: str) -> dict[str, list[str]]:
    """`dumpsys role` -> role -> holders. Falls back to empty dict."""
    out: dict[str, list[str]] = {}
    cur = None
    for ln in text.splitlines():
        m = re.match(r"^\s+(android\.app\.role\.\w+|[\w.]*\.role\.\w+):\s*$", ln)
        if m:
            cur = m.group(1)
            out.setdefault(cur, [])
            continue
        h = re.match(r"^\s+holders=(.*)$", ln)
        if h and cur:
            out[cur] = [x.strip() for x in h.group(1).split(",") if x.strip()]
    return out


def parse_overlays(text: str) -> list[dict]:
    rows, target = [], None
    for ln in text.splitlines():
        if not ln.strip():
            continue
        m = re.match(r"^\[(x| )\]\s+(\S+)", ln.strip()) or re.match(r"^(---)\s+(\S+)", ln.strip())
        if m and target:
            rows.append({"target": target, "overlay": m.group(2), "enabled": m.group(1) == "x"})
        elif not ln.startswith((" ", "[", "-")):
            target = ln.strip()
    return rows


def parse_component_list(text: str) -> list[str]:
    """Colon/comma separated component list from settings (e.g. enabled_notification_listeners)."""
    if not text or text in ("null", "n/a"):
        return []
    return [c.strip() for c in re.split(r"[:,]", text) if "/" in c or "." in c]


def parse_accessibility(text: str) -> dict:
    enabled = re.findall(r"Enabled services:\{\{?([^}]*)\}?\}", text)
    comps = sorted({c for grp in enabled for c in re.findall(r"[\w.]+/[\w.$]+", grp)})
    installed = sorted(set(re.findall(r"([\w.]+/[\w.$]+)\s*\n?.*?AccessibilityServiceInfo", text)))
    return {"enabled": comps, "installed_hint": installed}


def parse_accounts(text: str) -> list[dict]:
    return [{"name": n, "type": t} for n, t in sorted(set(re.findall(r"Account \{name=(.+?), type=(.+?)\}", text)))]


def parse_device_admins(text: str) -> list[str]:
    return sorted(set(re.findall(r"admin=ComponentInfo\{([^}]+)\}", text)))


def parse_usagestats(text: str) -> dict[str, dict]:
    best: dict[str, dict] = {}
    for m in re.finditer(r'package=(\S+) totalTimeUsed="([^"]*)" lastTimeUsed="([^"]*)"', text):
        pkg, total, last = m.groups()
        if pkg not in best or last > best[pkg]["last_used"]:
            best[pkg] = {"total_time": total, "last_used": last}
    return best


def parse_exit_info(text: str) -> list[dict]:
    recs = []
    for blk in re.split(r"(?m)^\s*ApplicationExitInfo #\d+:?", text)[1:]:
        t = re.search(r"timestamp=(\S+ \S+)", blk)
        pid = re.search(r"\bpid=(\d+)", blk)
        uid = re.search(r"realUid=(\d+)", blk)
        proc = re.search(r"process=(\S+)", blk)
        reason = re.search(r"reason=(\d+) \((.+?)\)(?: subreason|\s*$)", blk, re.M)
        desc = re.search(r"description=(.*)", blk)
        recs.append({"timestamp": t.group(1) if t else None, "pid": _int(pid.group(1)) if pid else None,
                     "uid": _int(uid.group(1)) if uid else None, "process": proc.group(1) if proc else None,
                     "reason_code": _int(reason.group(1)) if reason else None,
                     "reason": reason.group(2) if reason else None, "description": desc.group(1).strip() if desc else ""})
    return recs


def parse_alarms(text: str) -> dict[str, int]:
    return dict(Counter(m.group(1) for m in re.finditer(r"Alarm\{[0-9a-f]+ type \d+ [^}]*?([\w]+(?:\.[\w]+)+)\}", text)))


def parse_jobs(text: str) -> dict[str, int]:
    return dict(Counter(m.group(1) for m in re.finditer(r"JOB #[\w]+/\d+: [0-9a-f]+ ([\w.]+)/", text)))


def parse_notifications(text: str) -> dict[str, int]:
    return dict(Counter(m.group(1) for m in re.finditer(r"NotificationRecord\([0-9a-fx]+: pkg=([\w.]+)", text)))


def parse_netstats_uid(text: str) -> dict[int, dict[str, int]]:
    out: dict[int, dict[str, int]] = defaultdict(lambda: {"rx_bytes": 0, "tx_bytes": 0})
    uid = None
    for ln in text.splitlines():
        m = re.search(r"\buid=(\d+)\b", ln)
        if m and ("ident=" in ln or "set=" in ln or "tag=" in ln):
            uid = int(m.group(1))
            continue
        b = re.search(r"\brb=(\d+) rp=\d+ tb=(\d+)", ln)
        if b and uid is not None:
            out[uid]["rx_bytes"] += int(b.group(1))
            out[uid]["tx_bytes"] += int(b.group(2))
    return dict(out)


def parse_batterystats_power(text: str) -> list[dict]:
    return [{"uid": m.group(1), "mah": float(m.group(2))}
            for m in re.finditer(r"^\s+(?:Uid )?(u\d+[ais]\d+|\d+|1000|root|system|shell):?\s+([\d.]+)\s*(?:\(|mAh)", text, re.M)]


def parse_wifi(text: str) -> dict:
    info = re.search(r"mWifiInfo\s*(?:WifiInfo:)?\s*(.+)", text)
    return {"wifi_enabled": ("Wi-Fi is enabled" in text) if ("Wi-Fi is enabled" in text or "Wi-Fi is disabled" in text) else None,
            "wifi_info": info.group(1)[:400] if info else None,
            "configured_networks": len(re.findall(r"^\s*(?:ID:|networkId=|NetworkId:)", text, re.M))}


def parse_bonded_bt(text: str) -> list[dict]:
    m = re.search(r"Bonded devices:\n((?:[ \t]+.+\n?)+)", text)
    rows = []
    if m:
        for ln in m.group(1).splitlines():
            d = re.match(r"\s*([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})\s*(?:\[\s*(\S+)\s*\])?\s*(.*)", ln)
            if d:
                rows.append({"address": d.group(1), "type": d.group(2), "name": d.group(3).strip()})
    return rows


def parse_dns(text: str) -> list[str]:
    return sorted({x.strip() for grp in re.findall(r"DnsAddresses: \[([^\]]*)\]", text) for x in grp.split(",") if x.strip()})


def parse_service_list(text: str) -> list[str]:
    """`dumpsys -l`, `cmd -l`, or `service list` -> service names."""
    names = []
    for ln in text.splitlines():
        m = re.match(r"^\d+\s+([\w.\-:@/]+): \[", ln.strip()) or re.match(r"^\s{2}([\w.\-:@/]+)\s*$", ln)
        if m:
            names.append(m.group(1))
    return list(dict.fromkeys(names))


# ------------------------------------------------------------------ network
def hex_ip(h: str) -> str:
    raw = bytes.fromhex(h)
    if len(raw) == 4:
        return str(ipaddress.IPv4Address(raw[::-1]))
    ip = ipaddress.IPv6Address(b"".join(raw[i:i + 4][::-1] for i in range(0, 16, 4)))
    return str(ip.ipv4_mapped or ip)


def parse_proc_net(text: str, proto: str) -> list[dict]:
    rows, udp = [], proto.startswith(("udp", "raw"))
    for line in text.splitlines()[1:]:
        f = line.split()
        if len(f) < 10:
            continue
        try:
            lip, lport = f[1].split(":")
            rip, rport = f[2].split(":")
            state = ("UNCONN" if f[3] == "07" else "CONNECTED") if udp else TCP_STATES.get(f[3].upper(), f[3])
            tx, _, rx = f[4].partition(":")
            rows.append({"proto": proto, "local": f"{hex_ip(lip)}:{int(lport, 16)}", "remote": f"{hex_ip(rip)}:{int(rport, 16)}",
                         "state": state, "uid": int(f[7]), "inode": int(f[9]), "tx_queue": int(tx, 16), "rx_queue": int(rx, 16)})
        except ValueError:
            continue
    return rows


def parse_proc_net_unix(text: str) -> list[dict]:
    rows = []
    for ln in text.splitlines()[1:]:
        f = ln.split(None, 7)
        if len(f) >= 7:
            rows.append({"proto": "unix", "type": f[4], "state": f[5], "inode": _int(f[6]), "path": f[7] if len(f) > 7 else ""})
    return rows


def parse_proc_net_dev(text: str) -> list[dict]:
    rows = []
    for ln in text.splitlines()[2:]:
        name, _, rest = ln.partition(":")
        f = rest.split()
        if len(f) >= 16:
            rows.append({"iface": name.strip(), "rx_bytes": int(f[0]), "rx_packets": int(f[1]), "rx_errs": int(f[2]),
                         "tx_bytes": int(f[8]), "tx_packets": int(f[9]), "tx_errs": int(f[10])})
    return rows


def parse_if_inet6(text: str) -> list[dict]:
    rows = []
    for ln in text.splitlines():
        f = ln.split()
        if len(f) >= 6 and len(f[0]) == 32:
            addr = str(ipaddress.IPv6Address(bytes.fromhex(f[0])))
            rows.append({"iface": f[5], "family": "inet6", "address": f"{addr}/{int(f[2], 16)}"})
    return rows


def parse_ip_addr(text: str) -> list[dict]:
    ifs: list[dict] = []
    cur = None
    for ln in text.splitlines():
        m = re.match(r"^(\d+): ([^:@\s]+)(?:@\S+)?: <([^>]*)> (.*)$", ln)
        if m:
            rest = m.group(4)
            cur = {"index": int(m.group(1)), "name": m.group(2), "flags": m.group(3).split(","),
                   "mtu": _int((re.search(r"mtu (\d+)", rest) or [0, 0])[1]),
                   "state": (re.search(r"state (\w+)", rest) or [None, None])[1], "mac": None, "addresses": []}
            ifs.append(cur)
        elif cur:
            s = ln.strip()
            lm = re.match(r"link/(\w+) ([0-9a-fA-F:]{17})", s)
            if lm:
                cur["link_type"], cur["mac"] = lm.group(1), lm.group(2)
            am = re.match(r"(inet6?) (\S+)(?: .*?scope (\w+))?", s)
            if am:
                cur["addresses"].append({"family": am.group(1), "address": am.group(2), "scope": am.group(3)})
    return ifs


def parse_ip_route(text: str) -> list[dict]:
    rows = []
    for ln in text.splitlines():
        t = ln.split()
        if not t:
            continue
        r: dict[str, Any] = {"dst": t[0]}
        if t[0] in ("unreachable", "blackhole", "prohibit", "throw", "local", "broadcast", "multicast") and len(t) > 1:
            r["type"], r["dst"], t = t[0], t[1], t[1:]
        i = 1
        while i < len(t) - 1:
            r[t[i]] = t[i + 1]
            i += 2
        rows.append(r)
    return rows


def parse_ip_rule(text: str) -> list[dict]:
    return [{"priority": int(m.group(1)), "rule": m.group(2).strip()} for m in re.finditer(r"^(\d+):\s+(.*)$", text, re.M)]


def parse_ip_neigh(text: str) -> list[dict]:
    rows = []
    for ln in text.splitlines():
        t = ln.split()
        if len(t) >= 3 and "dev" in t:
            d = {"ip": t[0], "dev": t[t.index("dev") + 1], "mac": t[t.index("lladdr") + 1] if "lladdr" in t else None,
                 "state": t[-1], "router": "router" in t}
            rows.append(d)
    return rows


def parse_proc_net_arp(text: str) -> list[dict]:
    return [{"ip": f[0], "mac": f[3], "dev": f[5]} for f in (ln.split() for ln in text.splitlines()[1:]) if len(f) >= 6]


# ------------------------------------------------------------------ processes
def uid_from_user(user: str) -> int | None:
    if user in FIXED_UIDS:
        return FIXED_UIDS[user]
    m = re.match(r"^u(\d+)_([ais])(\d+)$", user)
    if m:
        base = {"a": 10000, "i": 90000, "s": 0}[m.group(2)]
        return int(m.group(1)) * 100000 + base + int(m.group(3))
    return int(user) if user.isdigit() else None


def parse_ps(text: str) -> list[dict]:
    lines = [ln for ln in text.splitlines() if ln.strip()]
    if not lines:
        return []
    header = lines[0].split()
    idx = {h.upper(): i for i, h in enumerate(header)}
    name_col = idx.get("NAME", idx.get("CMD", idx.get("COMMAND", idx.get("ARGS"))))
    if name_col is None or "PID" not in idx:
        return []
    rows = []
    for ln in lines[1:]:
        f = ln.split(None, len(header) - 1)
        if len(f) < len(header):
            continue
        try:
            user = f[idx.get("USER", 0)]
            uid = _int(f[idx["UID"]], -1) if "UID" in idx else uid_from_user(user)
            rows.append({"user": user, "uid": uid, "pid": int(f[idx["PID"]]),
                         "ppid": _int(f[idx["PPID"]]) if "PPID" in idx else None,
                         "rss_kb": _int(f[idx["RSS"]]) if "RSS" in idx else 0,
                         "state": f[idx["S"]] if "S" in idx else f[idx["STAT"]] if "STAT" in idx else None,
                         "name": f[name_col].strip()})
        except (ValueError, IndexError):
            continue
    return rows


# ------------------------------------------------------------------ logs
_LOG = re.compile(r"^(?P<ts>(?:\d{4}-)?\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+(?:\s?[+-]\d{4})?)\s+(?P<pid>\d+)\s+(?P<tid>\d+)\s+(?P<lvl>[VDIWEFS])\s+(?P<tag>.*?)\s*: (?P<msg>.*)$")


def parse_logcat(text: str) -> tuple[list[dict], int]:
    """Returns (entries, unparsed_line_count). Continuation lines are attached to the previous entry."""
    entries, bad = [], 0
    for ln in text.splitlines():
        if not ln.strip() or ln.startswith("-----"):
            continue
        m = _LOG.match(ln)
        if m:
            d = m.groupdict()
            d["pid"], d["tid"] = int(d["pid"]), int(d["tid"])
            entries.append(d)
        elif entries:
            entries[-1]["msg"] += "\n" + ln
        else:
            bad += 1
    return entries, bad


def summarize_log(entries: list[dict]) -> dict:
    return {"entries": len(entries), "first": entries[0]["ts"] if entries else None, "last": entries[-1]["ts"] if entries else None,
            "levels": dict(Counter(e["lvl"] for e in entries)),
            "top_tags": Counter(e["tag"] for e in entries).most_common(15),
            "top_pids": Counter(e["pid"] for e in entries).most_common(10)}


def parse_event_log(entries: list[dict]) -> dict:
    out: dict[str, list] = {"anr": [], "crash": [], "proc_died": [], "low_memory": []}
    for e in entries:
        tag, msg = e["tag"], e["msg"]
        if tag == "am_anr":
            out["anr"].append({"ts": e["ts"], "raw": msg[:200]})
        elif tag == "am_crash":
            out["crash"].append({"ts": e["ts"], "raw": msg[:200]})
        elif tag in ("am_proc_died", "am_kill"):
            out["proc_died"].append({"ts": e["ts"], "raw": msg[:160]})
        elif tag == "am_low_memory":
            out["low_memory"].append({"ts": e["ts"], "raw": msg[:80]})
    return out


def parse_logcat_buffers(text: str) -> list[str]:
    return list(dict.fromkeys(re.findall(r"^(\w+): ring buffer is", text, re.M)))


def parse_dropbox(text: str) -> dict[str, int]:
    return dict(Counter(m.group(1) for m in re.finditer(r"^\S+ \S+ (\w+) \(", text, re.M)))


# ------------------------------------------------------------------ misc
def parse_ls_long(text: str, base: str = "") -> list[dict]:
    """Fallback for `ls -lA` when `stat` is unavailable."""
    rows = []
    for ln in text.splitlines():
        m = re.match(r"^([-dlcbps])[rwxsStT-]{9}\S*\s+\d+\s+(\S+)\s+(\S+)\s+(\d+)\s+(\d{4}-\d{2}-\d{2} \d{2}:\d{2})(?::\d+)?\s+(.+)$", ln)
        if m:
            name = m.group(6).split(" -> ")[0]
            rows.append({"path": (base.rstrip("/") + "/" + name) if base else name,
                         "type": {"-": "file", "d": "dir", "l": "symlink"}.get(m.group(1), "other"),
                         "size": int(m.group(4)), "mtime": None, "mode": ln.split()[0], "owner": m.group(2)})
    return rows


def parse_sha_lines(text: str) -> dict[str, str]:
    out = {}
    for ln in text.splitlines():
        m = re.match(r"^([0-9a-f]{64}|[0-9a-f]{40}|[0-9a-f]{32})\s+\*?(.+)$", ln.strip())
        if m:
            out[m.group(2)] = m.group(1)
            continue
        m = re.match(r"^(?:SHA2?-?(?:256|1)?|MD5)\((.+)\)=\s*([0-9a-f]+)$", ln.strip(), re.I)
        if m:
            out[m.group(1)] = m.group(2)
    return out


def parse_power_supply(text: str) -> dict[str, dict[str, str]]:
    out: dict[str, dict[str, str]] = {}
    cur = None
    for ln in text.splitlines():
        if ln.startswith("== "):
            cur = out.setdefault(ln[3:].strip(), {})
        elif cur is not None and "=" in ln:
            k, _, v = ln.partition("=")
            cur[k.strip()] = v.strip()
    return out


def parse_kernel_config(text: str) -> dict[str, str]:
    return {m.group(1): m.group(2) for m in re.finditer(r"^(CONFIG_\w+)=(.+)$", text, re.M)}


def parse_vmstat(text: str) -> dict[str, int]:
    return {k: int(v) for k, v in (ln.split() for ln in text.splitlines() if len(ln.split()) == 2 and ln.split()[1].isdigit())}


def classify_partition(path: str) -> str:
    for prefix, name in (("/data/app", "data"), ("/data/", "data"), ("/system_ext/", "system_ext"), ("/system/", "system"),
                         ("/product/", "product"), ("/vendor/", "vendor"), ("/odm/", "odm"), ("/apex/", "apex"),
                         ("/oem/", "oem"), ("/mnt/", "mnt")):
        if path.startswith(prefix):
            return name
    return "unknown"
