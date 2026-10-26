"""Cross-source correlation (package <-> UID <-> process <-> socket <-> permission <-> capability) and baseline diff."""
from __future__ import annotations

from collections import Counter, defaultdict

from .collect_apps import _tp_perms
from .model import Ctx, table, details, fmt_bytes


def collect_correlation(ctx: Ctx) -> None:
    rt = ctx.data.get("runtime", {})
    net = ctx.data.get("network", {})
    by_uid_proc: dict = defaultdict(list)
    for p in ctx.procs:
        if p.get("uid") is not None:
            by_uid_proc[p["uid"] % 100000].append(p)
    socks: dict = defaultdict(list)
    for s in ctx.sockets:
        socks[s["uid"] % 100000].append(s)
    exits = defaultdict(Counter)
    for e in rt.get("exit_info", []):
        exits[e.get("process", "").split(":")[0]][e.get("reason") or "?"] += 1
    acct = net.get("uid_accounting", {})
    corr = []
    for pkg in sorted(ctx.third):
        r = ctx.packages.get(pkg, {})
        uid = int(r["uid"]) if str(r.get("uid") or "").isdigit() else None
        procs = [p for p in (by_uid_proc.get(uid, []) if uid is not None else []) if p["name"].split(":")[0] == pkg or True]
        sk = socks.get(uid, []) if uid is not None else []
        shared = len(ctx.uid_map.get(uid, [])) > 1 if uid is not None else False
        a = acct.get(str(uid), {})
        corr.append({"package": pkg, "uid": uid, "shared_uid": shared, "processes": [{"name": p["name"], "pid": p["pid"]} for p in procs],
                     "listening": [s["local"] for s in sk if s["state"] == "LISTEN"], "established": sum(1 for s in sk if s["state"] == "ESTABLISHED"),
                     "remote_ips": sorted({s["remote"].rsplit(":", 1)[0] for s in sk if s["state"] == "ESTABLISHED" and not s["remote"].startswith(("127.", "::1"))})[:20],
                     "sensitive_permissions": _tp_perms(ctx, r), "capabilities": r.get("capabilities", []), "appop_special": r.get("appop_special", []),
                     "roles": r.get("roles", []), "usage": rt.get("usage", {}).get(pkg), "alarms": rt.get("alarms_by_package", {}).get(pkg, 0),
                     "jobs": rt.get("jobs_by_package", {}).get(pkg, 0), "notifications": rt.get("notifications_by_package", {}).get(pkg, 0),
                     "exits": dict(exits.get(pkg, {})), "net_rx_bytes": a.get("rx_bytes"), "net_tx_bytes": a.get("tx_bytes"),
                     "apk_exported_unprotected": len((r.get("apk_analysis") or {}).get("exported_unprotected", []))})
    ctx.data["correlation"] = corr
    active = [c for c in corr if c["processes"] or c["listening"] or c["established"]]
    body = ("_Attribution is by UID; apps sharing a UID cannot be told apart by sockets or accounting. Observed links, not behaviour analysis._\n\n" +
            table(["Package", "UID", "Procs", "Listening", "Established", "Remote IPs", "Sensitive perms", "Capabilities", "RX/TX"], [
                [c["package"], c["uid"], len(c["processes"]), ", ".join(c["listening"]) or "-", c["established"], ", ".join(c["remote_ips"][:3]) or "-",
                 len(c["sensitive_permissions"]), ", ".join(c["capabilities"]) or "-",
                 f"{fmt_bytes(c['net_rx_bytes'] or 0)}/{fmt_bytes(c['net_tx_bytes'] or 0)}" if c["net_rx_bytes"] is not None else "n/a"]
                for c in sorted(active, key=lambda c: -(c["established"] + len(c["listening"])))[:60]]))
    ctx.add("Correlation (apps, UIDs, processes, network)", body)


def compare_baseline(old: dict, new: dict) -> dict:
    op, np_ = old.get("packages", {}) or {}, new.get("packages", {}) or {}
    diff = {"packages_added": sorted(set(np_) - set(op)), "packages_removed": sorted(set(op) - set(np_)), "version_changed": [],
            "installer_changed": [], "permissions_gained": {}, "permissions_lost": {}}
    for p in set(op) & set(np_):
        a, b = op[p], np_[p]
        if a.get("version_code") != b.get("version_code") or a.get("version_name") != b.get("version_name"):
            diff["version_changed"].append({"package": p, "old": a.get("version_name"), "new": b.get("version_name")})
        if a.get("installer") != b.get("installer"):
            diff["installer_changed"].append({"package": p, "old": a.get("installer"), "new": b.get("installer")})
        ga, gb = set(a.get("granted", [])), set(b.get("granted", []))
        if gb - ga:
            diff["permissions_gained"][p] = sorted(gb - ga)
        if ga - gb:
            diff["permissions_lost"][p] = sorted(ga - gb)
    watch = ("ro.build.fingerprint", "ro.build.version.security_patch", "ro.boot.verifiedbootstate", "ro.boot.flash.locked", "ro.debuggable", "ro.build.tags")
    ap, bp = old.get("props", {}) or {}, new.get("props", {}) or {}
    diff["props_changed"] = [{"prop": k, "old": ap.get(k), "new": bp.get(k)} for k in watch if ap.get(k) != bp.get(k)]
    keys = ("global/adb_enabled", "global/package_verifier_enable", "secure/enabled_accessibility_services", "secure/enabled_notification_listeners",
            "secure/default_input_method", "global/http_proxy", "global/private_dns_mode", "secure/always_on_vpn_app")
    so, sn = old.get("settings", {}) or {}, new.get("settings", {}) or {}
    diff["settings_changed"] = [{"setting": k, "old": so.get(k), "new": sn.get(k)} for k in keys if so.get(k) != sn.get(k)]
    def listen(d): return {f"{s['proto']} {s['local']}" for s in (d.get("network", {}) or {}).get("sockets", []) if s.get("state") == "LISTEN"}
    diff["listening_added"], diff["listening_removed"] = sorted(listen(new) - listen(old)), sorted(listen(old) - listen(new))
    def acc(d): return {f"{a['type']}:{a['name']}" for a in d.get("accounts", []) or []}
    diff["accounts_added"], diff["accounts_removed"] = sorted(acc(new) - acc(old)), sorted(acc(old) - acc(new))
    ft = lambda d: {f["title"] for f in d.get("findings", []) or []}
    diff["findings_new"], diff["findings_resolved"] = sorted(ft(new) - ft(old)), sorted(ft(old) - ft(new))
    diff["changed"] = any(bool(v) for v in diff.values())
    return diff


def render_baseline(diff: dict, path: str) -> str:
    body = f"Compared against `{path}`.\n\n"
    if not diff["changed"]:
        return body + "_No differences in the compared fields._"
    simple = [("Packages added", "packages_added"), ("Packages removed", "packages_removed"), ("Listening sockets added", "listening_added"),
              ("Listening sockets removed", "listening_removed"), ("Accounts added", "accounts_added"), ("Accounts removed", "accounts_removed"),
              ("New findings", "findings_new"), ("Resolved findings", "findings_resolved")]
    body += table(["Change", "Items"], [[t, ", ".join(diff[k]) or "-"] for t, k in simple])
    for title, key, cols in (("Version changes", "version_changed", ("package", "old", "new")), ("Installer changes", "installer_changed", ("package", "old", "new")),
                             ("Property changes", "props_changed", ("prop", "old", "new")), ("Setting changes", "settings_changed", ("setting", "old", "new"))):
        if diff[key]:
            body += f"\n\n**{title}**\n\n" + table(list(cols), [[r[c] for c in cols] for r in diff[key]])
    for title, key in (("Permissions gained", "permissions_gained"), ("Permissions lost", "permissions_lost")):
        if diff[key]:
            body += f"\n\n**{title}**\n\n" + table(["Package", "Permissions"], [[p, ", ".join(v)] for p, v in diff[key].items()])
    return body
