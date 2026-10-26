"""Application enumeration: packages, permissions, app-ops, roles, components, capabilities, review scoring."""
from __future__ import annotations

import re
from collections import Counter, defaultdict

from . import parsers as P
from .adb import OK
from .model import Ctx, Spec, table, fence, details, or_na, fmt_bytes, clip

SENSITIVE_PERMS = {
    "CAMERA", "RECORD_AUDIO", "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION", "ACCESS_BACKGROUND_LOCATION",
    "READ_SMS", "SEND_SMS", "RECEIVE_SMS", "RECEIVE_MMS", "RECEIVE_WAP_PUSH", "READ_CONTACTS", "WRITE_CONTACTS", "GET_ACCOUNTS",
    "READ_CALL_LOG", "WRITE_CALL_LOG", "CALL_PHONE", "PROCESS_OUTGOING_CALLS", "READ_PHONE_STATE", "READ_PHONE_NUMBERS",
    "ANSWER_PHONE_CALLS", "READ_CALENDAR", "WRITE_CALENDAR", "BODY_SENSORS", "BODY_SENSORS_BACKGROUND", "ACTIVITY_RECOGNITION",
    "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE", "MANAGE_EXTERNAL_STORAGE", "READ_MEDIA_IMAGES", "READ_MEDIA_VIDEO",
    "READ_MEDIA_AUDIO", "SYSTEM_ALERT_WINDOW", "REQUEST_INSTALL_PACKAGES", "QUERY_ALL_PACKAGES", "BIND_ACCESSIBILITY_SERVICE",
    "BIND_DEVICE_ADMIN", "PACKAGE_USAGE_STATS", "BIND_NOTIFICATION_LISTENER_SERVICE", "BLUETOOTH_CONNECT", "BLUETOOTH_SCAN",
    "NEARBY_WIFI_DEVICES", "POST_NOTIFICATIONS", "USE_BIOMETRIC", "USE_FULL_SCREEN_INTENT", "SCHEDULE_EXACT_ALARM",
}
SMS_CALL_PERMS = {"READ_SMS", "SEND_SMS", "RECEIVE_SMS", "READ_CALL_LOG", "PROCESS_OUTGOING_CALLS"}
# (op, label, review weight, tag)
APPOPS = [("REQUEST_INSTALL_PACKAGES", "Allowed to install other apps", 2, "installs apps"),
          ("SYSTEM_ALERT_WINDOW", "Allowed to draw over other apps", 2, "overlay"),
          ("MANAGE_EXTERNAL_STORAGE", "All-files access", 1, "all-files"),
          ("GET_USAGE_STATS", "Usage-stats access", 1, "usage-stats"),
          ("WRITE_SETTINGS", "Allowed to modify system settings", 1, "write-settings"),
          ("ACCESS_NOTIFICATIONS", "Notification access", 1, "notif-access"),
          ("SCHEDULE_EXACT_ALARM", "Exact alarms", 0, "exact-alarm"),
          ("REQUEST_DELETE_PACKAGES", "Allowed to request package deletion", 0, "delete-pkgs"),
          ("MANAGE_MEDIA", "Media management", 0, "manage-media"),
          ("INTERACT_ACROSS_PROFILES", "Cross-profile interaction", 0, "cross-profile")]
# (key, label, pm query kind, intent action, review weight, tag)
CAPABILITIES = [
    ("boot", "Boot-time receivers", "receivers", "android.intent.action.BOOT_COMPLETED", 0, "boot rcv"),
    ("locked_boot", "Direct-boot receivers", "receivers", "android.intent.action.LOCKED_BOOT_COMPLETED", 0, "locked-boot rcv"),
    ("a11y", "Accessibility services", "services", "android.accessibilityservice.AccessibilityService", 3, "a11y svc"),
    ("notif", "Notification listeners", "services", "android.service.notification.NotificationListenerService", 1, "notif listener"),
    ("admin", "Device-admin receivers", "receivers", "android.app.action.DEVICE_ADMIN_ENABLED", 3, "admin rcv"),
    ("vpn", "VPN services", "services", "android.net.VpnService", 1, "vpn svc"),
    ("callscreen", "Call-screening services", "services", "android.telecom.CallScreeningService", 2, "call screen"),
    ("incall", "In-call services", "services", "android.telecom.InCallService", 1, "incall"),
    ("ime", "Input methods (keyboards)", "services", "android.view.InputMethod", 1, "ime"),
    ("autofill", "Autofill services", "services", "android.service.autofill.AutofillService", 1, "autofill"),
    ("voice", "Voice interaction services", "services", "android.service.voice.VoiceInteractionService", 1, "voice"),
    ("smsrcv", "SMS_RECEIVED receivers", "receivers", "android.provider.Telephony.SMS_RECEIVED", 2, "sms rcv"),
    ("wappush", "WAP push receivers", "receivers", "android.provider.Telephony.WAP_PUSH_DELIVER", 1, "wap-push rcv"),
    ("phonestate", "Call-state receivers", "receivers", "android.intent.action.PHONE_STATE", 0, "phone-state rcv"),
    ("qstile", "Quick-settings tiles", "services", "android.service.quicksettings.action.QS_TILE", 0, "qs tile"),
]
AOSP_ROLES = ["ASSISTANT", "BROWSER", "CALL_REDIRECTION", "CALL_SCREENING", "DIALER", "EMERGENCY", "HOME", "SMS", "NOTES"]
NO_STORE = (None, "", "null", "none", "com.android.shell")


def _norm_installer(v):
    return None if v in NO_STORE else v


def prepare_packages(ctx: Ctx) -> None:
    adb, args = ctx.adb, ctx.args
    ctx.progress("package listing")
    per_user: dict[int, dict] = {}
    cur_first = sorted(ctx.target_users, key=lambda u: u != ctx.current_user)
    for u in cur_first:
        r = adb.first_ok([f"pm list packages --user {u} -f -i -U --show-versioncode", f"pm list packages --user {u} -f -i -U",
                          f"pm list packages --user {u} -f -i", f"pm list packages --user {u} -f", "pm list packages -f"],
                         label=f"pm-list-u{u}", timeout=90)
        apps = P.parse_pm_list(r.text) if r.ok else {}
        sets = {"all": set(apps)}
        for key, flag in (("third", "-3"), ("system", "-s"), ("disabled", "-d"), ("enabled", "-e")):
            q = adb.shell(f"pm list packages {flag} --user {u}", label=f"pm-list-{key}-u{u}", timeout=60)
            sets[key] = P.parse_pm_names(q.text) if q.ok else set()
        if not sets["system"]:
            sets["system"] = sets["all"] - sets["third"]
        per_user[u] = {"apps": apps, "sets": sets}
    for u in cur_first:
        for pkg, a in per_user[u]["apps"].items():
            rec = ctx.packages.setdefault(pkg, {"name": pkg, "path": a["path"], "installer": a["installer"], "uid": a["uid"],
                                                "version_code": a["version_code"], "users": {}})
            rec["users"][str(u)] = {"present": True, "third_party": pkg in per_user[u]["sets"]["third"],
                                    "disabled": pkg in per_user[u]["sets"]["disabled"], "enabled_listed": pkg in per_user[u]["sets"]["enabled"]}
            rec["path"] = rec["path"] or a["path"]
    ctx.third = set().union(*(per_user[u]["sets"]["third"] for u in per_user)) if per_user else set()
    ctx.disabled = per_user.get(ctx.current_user, {"sets": {"disabled": set()}})["sets"]["disabled"]
    ctx.data["per_user_packages"] = {str(u): {k: sorted(v) for k, v in d["sets"].items()} for u, d in per_user.items()}
    if ctx.level >= 1:
        allp = P.parse_pm_names(adb.text(f"pm list packages -u --user {ctx.current_user}", label="pm-list-uninstalled", timeout=60))
        ctx.data["uninstalled_with_data"] = sorted(allp - set(ctx.packages))
    if args.skip_details:
        _finish_records(ctx, {})
        return
    ctx.progress("package details (dumpsys package) - can take a minute")
    r = adb.shell("dumpsys package", label="dumpsys-package-full", timeout=max(args.long_timeout, 300))
    info = P.parse_dumpsys_packages(r.stdout) if r.ok else {}
    comps = P.parse_resolver_tables(r.stdout) if r.ok else {}
    auth = P.parse_provider_authorities(r.stdout) if r.ok else {}
    missing = [p for p in sorted(ctx.packages if not info else ctx.third) if p not in info and P.PKG_RE.match(p)]
    if missing:
        ctx.progress(f"per-package fallback for {len(missing)} packages")
        texts, _ = adb.batch(missing, "dumpsys package $p", chunk=10, label="dumpsys-package-batch", timeout=120)
        for t in texts.values():
            info.update(P.parse_dumpsys_packages(t))
    _finish_records(ctx, info, comps, auth)
    ctx.data["packages"] = ctx.packages


def _finish_records(ctx: Ctx, info: dict, comps: dict | None = None, auth: dict | None = None) -> None:
    by_pkg: dict[str, dict] = defaultdict(lambda: defaultdict(dict))
    for kind, cdict in (comps or {}).items():
        for comp, f in cdict.items():
            pkg, _, cls = comp.partition("/")
            by_pkg[pkg][kind][cls] = {"actions": sorted(f["actions"]), "categories": sorted(f["categories"]), "schemes": sorted(f["schemes"])}
    for pkg, rec in ctx.packages.items():
        d = info.get(pkg, {})
        rec.update({k: v for k, v in d.items() if v not in (None, [], {})} if d else {})
        rec["uid"] = rec.get("uid") or d.get("user_id")
        rec["installer"] = rec.get("installer") or d.get("installer")
        rec["partition"] = P.classify_partition(rec.get("code_path") or rec.get("path") or "")
        rec["third_party"] = pkg in ctx.third
        rec["has_details"] = bool(d)
        rec["components"] = {k: v for k, v in by_pkg.get(pkg, {}).items()}
        rec["provider_authorities"] = (auth or {}).get(pkg, [])
        if rec.get("uid") and str(rec["uid"]).isdigit():
            lst = ctx.uid_map.setdefault(int(rec["uid"]), [])
            if pkg not in lst:
                lst.append(pkg)


def collect_package_paths_hashes(ctx: Ctx) -> None:
    """APK paths (base + splits), sizes and device-side hashes."""
    adb, args = ctx.adb, ctx.args
    scope_all = ctx.level >= 2 or getattr(args, "apk_scope", "third") == "all"
    pkgs = sorted(p for p in ctx.packages if P.PKG_RE.match(p) and (scope_all or p in ctx.third))
    ctx.progress(f"APK paths for {len(pkgs)} packages")
    texts, _ = adb.batch(pkgs, "pm path $p 2>&1", chunk=40, label="pm-path", timeout=90)
    for p in pkgs:
        paths = P.parse_pm_path(texts.get(p, ""))
        if paths:
            ctx.packages[p]["apk_paths"] = paths
    do_hash = args.hash_apps or ctx.level >= 2
    if not do_hash:
        return
    hash_scope_all = args.hash_scope == "all" or (args.hash_scope == "auto" and ctx.level >= 2)
    targets = [path for p in pkgs if (hash_scope_all or p in ctx.third) for path in ctx.packages[p].get("apk_paths", [])]
    tools = ctx.caps["tools"]
    candidates = [("sha256", "sha256sum"), ("sha256", "toybox sha256sum"), ("sha256", "openssl dgst -sha256")]
    if tools.get("sha256sum") is False:
        candidates = candidates[1:]
    hashes: dict[str, str] = {}
    ctx.progress(f"hashing {len(targets)} APK files on device")
    import shlex
    chosen = None
    for i in range(0, len(targets), 20):
        part = " ".join(shlex.quote(t) for t in targets[i:i + 20])
        for tool in ([chosen] if chosen else [t for _, t in candidates]):
            r = adb.shell(f"{tool} {part}", label="apk-hash", timeout=args.long_timeout)
            got = P.parse_sha_lines(r.stdout) if (r.status == OK or r.partial) else {}
            if got:
                hashes.update(got)
                chosen = tool
                break
    if ctx.caps.get("stat_c") and targets:
        sizes: dict[str, int] = {}
        for i in range(0, len(targets), 40):
            part = " ".join(shlex.quote(t) for t in targets[i:i + 40])
            r = adb.shell(f"stat -c '%s|%n' {part}", label="apk-size", timeout=60)
            for ln in r.text.splitlines():
                s, _, n = ln.partition("|")
                if s.isdigit():
                    sizes[n] = int(s)
        for p in pkgs:
            ctx.packages[p]["apk_sizes"] = {x: sizes[x] for x in ctx.packages[p].get("apk_paths", []) if x in sizes}
    for p in pkgs:
        hs = {x: hashes[x] for x in ctx.packages[p].get("apk_paths", []) if x in hashes}
        if hs:
            ctx.packages[p]["apk_sha256"] = hs
    ctx.data["apk_hash_coverage"] = {"files_targeted": len(targets), "files_hashed": len(hashes)}


def collect_permissions_catalog(ctx: Ctx) -> None:
    specs = [Spec("perm_groups", "Permission groups", ["pm list permission-groups"], 1, show=0),
             Spec("perm_catalog", "Permission catalog (grouped, with protection levels)",
                  ["pm list permissions -g -f", "pm list permissions -g", "pm list permissions"], 1, parser=P.parse_permission_list, show=0)]
    items = ctx.run_specs(specs)
    cat = items[1].parsed or {"groups": {}, "permissions": {}}
    ctx.data["permission_catalog"] = cat
    dangerous = sorted(k for k, v in cat["permissions"].items() if "dangerous" in v.get("protection", ""))
    body = table(["Metric", "Count"], [["Permission groups", len(cat["groups"])], ["Permissions", len(cat["permissions"])], ["Dangerous", len(dangerous)]])
    body += "\n\n" + ctx.render_items(items, specs)
    ctx.add("Permission catalog", body)


def _tp_perms(ctx: Ctx, d: dict) -> list[str]:
    cat = (ctx.data.get("permission_catalog") or {}).get("permissions", {})
    dang = {k for k, v in cat.items() if "dangerous" in v.get("protection", "")}
    out = {P_.rsplit(".", 1)[-1] for P_ in d.get("granted", []) if (P_ in dang or P_.rsplit(".", 1)[-1] in SENSITIVE_PERMS)}
    return sorted(out)


def collect_app_security(ctx: Ctx) -> None:
    """App-ops, roles, intent-declared capabilities, a11y/IME/overlay/VPN/admin settings, review scoring."""
    adb, args = ctx.adb, ctx.args
    ctx.progress("app-ops, roles and capability queries")
    holders: dict[str, list[str]] = {}
    for op, *_ in APPOPS:
        r = adb.shell(f"cmd appops query-op {op} allow", label=f"appops-query-{op}", timeout=60)
        holders[op] = P.parse_appop_holders(r.text) if r.ok else []
    comps: dict[str, dict[str, set]] = {}
    for key, _l, kind, action, _w, _t in CAPABILITIES:
        r = adb.first_ok([f"pm query-{kind} --brief -a {action}", f"pm query-{kind} -a {action}"], label=f"pm-query-{key}", timeout=60)
        comps[key] = {k: v for k, v in P.parse_components(r.text).items()} if r.ok else {}
    roles = P.parse_roles(adb.text("dumpsys role", label="dumpsys-role", timeout=60))
    if not roles:
        for name in AOSP_ROLES:
            role = f"android.app.role.{name}"
            r = adb.shell(f"cmd role get-role-holders --user {ctx.current_user} {role}", label=f"role-{name}", timeout=30)
            roles[role] = P.parse_appop_holders(r.text) if r.ok else []
    # per-package app-ops
    scope = sorted(p for p in ctx.packages if P.PKG_RE.match(p) and (ctx.level >= 2 or p in ctx.third))
    users = ctx.target_users if ctx.level >= 2 else [ctx.current_user]
    for u in users:
        texts, rs = adb.batch(scope, f"cmd appops get --user {u} $p 2>&1", chunk=25, label=f"appops-get-u{u}", timeout=90)
        if not any(P.parse_appops_get(t) for t in texts.values()):
            texts, rs = adb.batch(scope, "appops get $p 2>&1", chunk=25, label="appops-get-legacy", timeout=90)
        for p, t in texts.items():
            ops = P.parse_appops_get(t)
            if ops:
                ctx.packages[p].setdefault("appops", {})[str(u)] = ops
    # settings-derived
    st = ctx.setting
    ime_all = adb.text("ime list -a -s", label="ime-list", timeout=30).split()
    overlays = P.parse_overlays(adb.text("cmd overlay list", label="overlay-list", timeout=60))
    a11y_dump = P.parse_accessibility(adb.text("dumpsys accessibility", label="dumpsys-accessibility", timeout=60))
    notif_listeners = P.parse_component_list(st("secure", "enabled_notification_listeners"))
    a11y_enabled = P.parse_component_list(st("secure", "enabled_accessibility_services")) or a11y_dump["enabled"]
    admins = ctx.data.get("security", {}).get("device_admins", [])
    info = {
        "appop_holders": holders, "roles": roles, "components": {k: {p: sorted(c) for p, c in v.items()} for k, v in comps.items()},
        "enabled_accessibility": a11y_enabled, "enabled_notification_listeners": notif_listeners,
        "default_ime": st("secure", "default_input_method"), "installed_imes": ime_all, "autofill_service": st("secure", "autofill_service"),
        "assistant": st("secure", "assistant"), "voice_interaction": st("secure", "voice_interaction_service"),
        "always_on_vpn": st("secure", "always_on_vpn_app"), "always_on_vpn_lockdown": st("secure", "always_on_vpn_lockdown"),
        "overlays": overlays, "device_admins": admins,
    }
    ctx.data["app_security"] = info
    for pkg in ctx.third:
        rec = ctx.packages.get(pkg, {})
        rec["capabilities"] = [k for k, *_ in CAPABILITIES if pkg in comps.get(k, {})]
        rec["appop_special"] = [op for op, *_ in APPOPS if pkg in holders.get(op, [])]
        rec["roles"] = [r.rsplit(".", 1)[-1] for r, h in roles.items() if pkg in h]
        rec["enabled_a11y"] = [c for c in a11y_enabled if c.startswith(pkg + "/")]
        rec["enabled_notif_listener"] = [c for c in notif_listeners if c.startswith(pkg + "/")]
    # review scoring (third-party)
    attention: dict[str, list[tuple[int, str]]] = defaultdict(list)
    for pkg in ctx.third:
        rec = ctx.packages.get(pkg, {})
        fl = rec.get("flags", [])
        if "DEBUGGABLE" in fl:
            attention[pkg].append((4, "debuggable"))
        if "TEST_ONLY" in fl:
            attention[pkg].append((4, "test-only build"))
        if _norm_installer(rec.get("installer")) is None:
            attention[pkg].append((3, "no store installer"))
        for op, _l, w, tag in APPOPS:
            if w and pkg in holders.get(op, []):
                attention[pkg].append((w, tag))
        for key, _l, _k, _a, w, tag in CAPABILITIES:
            if w and pkg in comps.get(key, {}):
                attention[pkg].append((w, tag))
    ctx.data["review_list"] = sorted(
        ([p, sum(w for w, _ in r), ", ".join(t for _, t in r)] for p, r in attention.items() if sum(w for w, _ in r) >= 4),
        key=lambda x: (-x[1], x[0]))
    # report
    body = "**Special app-op grants** (`cmd appops query-op <OP> allow`)\n\n" + table(
        ["Capability", "App op", "Third-party holders", "System holders"],
        [[lbl, op, ", ".join(p for p in holders.get(op, []) if p in ctx.third) or "-",
          len([p for p in holders.get(op, []) if p not in ctx.third])] for op, lbl, *_ in APPOPS])
    body += "\n\n**Manifest-declared capabilities** (`pm query-*`)\n\n" + table(
        ["Capability", "Third-party apps", "System apps"],
        [[lbl, ", ".join(sorted(p for p in comps.get(k, {}) if p in ctx.third)) or "-", len([p for p in comps.get(k, {}) if p not in ctx.third])]
         for k, lbl, *_ in CAPABILITIES])
    body += "\n\n**Role holders**\n\n" + table(["Role", "Holder(s)"], [[r.rsplit(".", 1)[-1], ", ".join(h) or "-"] for r, h in sorted(roles.items())])
    body += "\n\n**Enabled special services and defaults**\n\n" + table(["Item", "Value"], [
        ["Accessibility services enabled", ", ".join(a11y_enabled) or "none"],
        ["Notification listeners enabled", ", ".join(notif_listeners) or "none"],
        ["Default input method", info["default_ime"]], ["Installed input methods", ", ".join(ime_all) or "n/a"],
        ["Autofill service", info["autofill_service"]], ["Assistant / voice interaction", f"{info['assistant']} / {info['voice_interaction']}"],
        ["Always-on VPN / lockdown", f"{info['always_on_vpn']} / {info['always_on_vpn_lockdown']}"],
        ["Device administrators", ", ".join(admins) or "none"],
        ["Overlay packages (enabled / total)", f"{sum(1 for o in overlays if o['enabled'])} / {len(overlays)}"]])
    if overlays:
        body += "\n\n" + details(f"Runtime resource overlays ({len(overlays)})", table(["Target", "Overlay", "Enabled"], [[o["target"], o["overlay"], o["enabled"]] for o in overlays]))
    body += "\n\n### Review list (third-party apps)\n\n_Ranked by a simple score (debuggable/test-only 4, no store installer 3, accessibility/device-admin 3, install/overlay/SMS-receiver/call-screening 2, others 1). A high score means 'look at this first', not 'malicious'._\n\n"
    body += table(["Package", "Score", "Reasons"], ctx.data["review_list"][:40])
    ctx.add("Application security surface", body)


def collect_apps_section(ctx: Ctx) -> None:
    adb, args = ctx.adb, ctx.args
    recs, third = ctx.packages, ctx.third
    system = set(recs) - third
    inst = Counter((_norm_installer(recs[p].get("installer")) or "none") for p in third)
    body = table(["Metric", "Count"], [["Total packages (target users)", len(recs)], ["Third-party", len(third)], ["System", len(system)],
                                       ["Disabled (current user)", len(ctx.disabled)], ["With full details", sum(1 for r in recs.values() if r.get("has_details"))],
                                       ["Updated system apps", sum(1 for r in recs.values() if "UPDATED_SYSTEM_APP" in r.get("flags", []))]])
    body += "\n\n**Third-party apps by installer**\n\n" + table(["Installer", "Apps"], [[k, v] for k, v in inst.most_common()])
    body += "\n\n**Packages per partition**\n\n" + table(["Partition", "Packages"], [[k, v] for k, v in Counter(r.get("partition") for r in recs.values()).most_common()])
    if len(ctx.target_users) > 1:
        body += "\n\n**Per-user package counts**\n\n" + table(["User", "All", "Third-party", "Disabled"], [
            [u, len(d["all"]), len(d["third"]), len(d["disabled"])] for u, d in ctx.data["per_user_packages"].items()])
    rows, sens_rows = [], []
    for pkg in sorted(third):
        r = recs[pkg]
        granted = _tp_perms(ctx, r)
        notes = []
        fl = r.get("flags", [])
        for flag, note in (("DEBUGGABLE", "debuggable"), ("TEST_ONLY", "test-only"), ("ALLOW_BACKUP", "backup allowed"), ("USES_CLEARTEXT_TRAFFIC", "cleartext traffic")):
            if flag in fl:
                notes.append(note)
        if pkg in ctx.disabled:
            notes.append("disabled")
        notes += r.get("appop_special", []) + r.get("capabilities", [])
        if _norm_installer(r.get("installer")) is None:
            notes.append("no store installer")
        try:
            if r.get("target_sdk") and int(r["target_sdk"]) < 28:
                notes.append(f"old targetSdk {r['target_sdk']}")
        except ValueError:
            pass
        sig = (r.get("signing") or {}).get("hashes", [])
        row = [pkg, or_na(r.get("version_name")), or_na(r.get("uid")), f"{or_na(r.get('min_sdk'))}/{or_na(r.get('target_sdk'))}",
               or_na(r.get("installer")), or_na(r.get("first_install")), or_na(r.get("last_update")),
               f"{len(granted)} of {r.get('requested', 0)}", ", ".join(notes), ",".join(sig)[:16] or "n/a",
               len(r.get("apk_paths", [])) or "n/a"]
        if args.hash_apps or ctx.level >= 2:
            row.append(next(iter(r.get("apk_sha256", {}).values()), "n/a"))
        rows.append(row)
        if granted:
            sens_rows.append((len(granted), [pkg, ", ".join(granted)]))
    headers = ["Package", "Version", "UID", "min/target SDK", "Installer", "First install", "Last update", "Sensitive perms (granted of requested)",
               "Notes", "Signer hash", "APKs"]
    if args.hash_apps or ctx.level >= 2:
        headers.append("SHA-256 (first APK)")
    body += "\n\n### Third-party apps\n\n" + table(headers, rows)
    sens_rows.sort(key=lambda t: (-t[0], t[1][0]))
    body += "\n\n### Third-party apps with sensitive permissions granted\n\n" + table(["Package", "Granted"], [r for _, r in sens_rows])
    if args.full_perms or ctx.level >= 2:
        parts = []
        for pkg in sorted(third):
            r = recs[pkg]
            gr = set(r.get("granted", []))
            denied = [x for x in r.get("requested_perms", []) if x not in gr]
            parts.append(details(pkg, "**Granted**\n\n" + fence("\n".join(sorted(gr)) or "none") + "\n\n**Requested but not granted**\n\n" +
                                 fence("\n".join(sorted(denied)) or "none")))
        body += "\n\n### Full permission lists\n\n" + "\n\n".join(parts)
    body += "\n\n### Disabled packages\n\n" + (fence("\n".join(sorted(ctx.disabled))) if ctx.disabled else "_none_")
    apex = adb.text("pm list packages --apex-only --show-versioncode", label="pm-apex")
    arows = re.findall(r"^package:(\S+)\s+versionCode:(\d+)", apex, re.M)
    if arows:
        body += "\n\n" + details(f"Mainline (APEX) modules ({len(arows)})", table(["Module", "versionCode"], [list(x) for x in sorted(arows)]))
    ctx.data["apex_modules"] = [{"module": m, "version_code": v} for m, v in arows]
    lines = [f"{p}  {recs[p].get('version_name') or ''}  [{recs[p].get('partition')}]  uid={recs[p].get('uid')}".rstrip() for p in sorted(system)]
    body += "\n\n" + details(f"System packages ({len(system)})", fence("\n".join(lines)))
    body += "\n\n" + details("Components with intent filters (per third-party app)", table(
        ["Package", "Activities", "Services", "Receivers", "Providers", "Authorities"],
        [[p, len(recs[p].get("components", {}).get("activity", {})), len(recs[p].get("components", {}).get("service", {})),
          len(recs[p].get("components", {}).get("receiver", {})), len(recs[p].get("components", {}).get("provider", {})),
          ", ".join(recs[p].get("provider_authorities", []))] for p in sorted(third)])) + \
        "\n\n_Resolver tables list only components that declare intent filters; the exported flag and non-filtered components need APK analysis (`--analyze-apks`)._"
    ctx.add("Installed applications", body)
    ctx.data["packages"] = recs
