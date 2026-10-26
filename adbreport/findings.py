"""Evidence-based findings. `observations` are facts read from the device; `heuristics` are inferences and are labelled as such."""
from __future__ import annotations

import datetime as dt

from .adb import DENIED, FAILED, TIMEOUT, UNSUPPORTED
from .model import Ctx
from .collect_apps import _norm_installer, SMS_CALL_PERMS


def run_rules(ctx: Ctx) -> None:
    g = ctx.props.get
    st = ctx.setting
    gp = [ctx.data.get("getprop_cmd")] if ctx.data.get("getprop_cmd") else []
    sec = ctx.data.get("security", {})
    app = ctx.data.get("app_security", {})
    third = ctx.third
    recs = ctx.packages

    patch = g("ro.build.version.security_patch", "")
    try:
        age = (dt.date.today() - dt.date.fromisoformat(patch)).days
        if age > 365:
            ctx.find("Security patch level is old", "medium", "medium", "platform", [f"ro.build.version.security_patch = {patch} ({age} days old)"],
                     ["Devices this far behind on patches are likely missing public fixes (depends on the vendor's patch cadence)."], gp,
                     "Check for system updates.")
    except ValueError:
        pass
    if g("ro.debuggable") == "1":
        ctx.find("Debuggable build", "high", "high", "platform", ["ro.debuggable = 1"], [], gp)
    if g("ro.secure") == "0":
        ctx.find("ro.secure=0 (adb may run as root)", "high", "high", "platform", ["ro.secure = 0"], [], gp)
    if "test-keys" in (g("ro.build.tags") or ""):
        ctx.find("Build signed with test-keys", "medium", "medium", "platform", [f"ro.build.tags = {g('ro.build.tags')}"], ["Typically a custom or unofficial ROM."], gp)
    vb = g("ro.boot.verifiedbootstate")
    if vb and vb != "green":
        ctx.find(f"Verified boot state is {vb}", "medium", "high", "boot", [f"ro.boot.verifiedbootstate = {vb}"], [], gp)
    if g("ro.boot.flash.locked") == "0" or g("ro.boot.vbmeta.device_state") == "unlocked":
        ctx.find("Bootloader unlocked", "medium", "high", "boot", [f"ro.boot.flash.locked = {g('ro.boot.flash.locked')}", f"ro.boot.vbmeta.device_state = {g('ro.boot.vbmeta.device_state')}"], [], gp)
    se = sec.get("selinux")
    if se and se != "Enforcing":
        ctx.find(f"SELinux is {se}", "high", "high", "platform", [f"getenforce = {se}"], [], ctx.evidence("selinux_getenforce"))
    if g("ro.crypto.state") == "unencrypted":
        ctx.find("Device storage is not encrypted", "high", "high", "platform", ["ro.crypto.state = unencrypted"], [], gp)
    ks = sec.get("kernel_sysctl", {})
    weak = [f"{k}={v}" for k, v in ks.items() if (k == "kptr_restrict" and v == "0") or (k == "dmesg_restrict" and v == "0") or (k == "randomize_va_space" and v == "0")]
    if weak:
        ctx.find("Weak kernel hardening sysctls", "low", "medium", "kernel", weak, [], ctx.evidence("kernel_sysctl"))
    root_pk = [p for p in ("com.topjohnwu.magisk", "io.github.vvb2060.magisk", "eu.chainfire.supersu", "com.noshufou.android.su", "com.koushikdutta.superuser",
                           "me.weishu.kernelsu", "com.thirdparty.superuser", "com.kingroot.kinguser") if p in recs]
    if sec.get("su_paths") or root_pk:
        ctx.find("Root indicators present", "high", "medium", "root", [f"su-related paths: {sec.get('su_paths') or 'none'}", f"root-manager packages: {root_pk or 'none'}"],
                 ["Presence of these artifacts suggests the device may be rooted; absence does not prove it is not."], ctx.evidence("su_paths"))
    port = sec.get("tcp_port")
    if port and port not in ("0", "-1"):
        ctx.find("ADB over TCP configured", "medium", "high", "adb", [f"service.adb.tcp.port / persist.adb.tcp.port = {port}"], [], gp)
    if st("global", "adb_wifi_enabled") == "1":
        ctx.find("Wireless debugging enabled", "info", "high", "adb", ["global/adb_wifi_enabled = 1"], [])
    if st("global", "adb_enabled") == "1":
        ctx.find("USB debugging enabled", "info", "high", "adb", ["global/adb_enabled = 1"], [])
    if st("global", "package_verifier_enable") == "0":
        ctx.find("Package verifier disabled", "medium", "high", "settings", ["global/package_verifier_enable = 0"], [])
    if st("global", "http_proxy") not in ("n/a", ":0", ""):
        ctx.find("Global HTTP proxy configured", "medium", "high", "network", [f"global/http_proxy = {st('global', 'http_proxy')}"],
                 ["Traffic may be routed through an intermediary."], ctx.evidence("connectivity"))
    tp = lambda lst: [c for c in lst if c.split("/")[0] in third]
    a11y = tp(app.get("enabled_accessibility", []))
    if a11y:
        ctx.find("Third-party accessibility service enabled", "medium", "high", "app-privilege", [f"enabled: {', '.join(a11y)}"],
                 ["Accessibility services can observe and act on screen content; legitimate for assistive apps, abusable by malicious ones."])
    nl = tp(app.get("enabled_notification_listeners", []))
    if nl:
        ctx.find("Third-party notification listener enabled", "low", "high", "app-privilege", [f"enabled: {', '.join(nl)}"])
    adm = [a for a in app.get("device_admins", []) if a.split("/")[0] in third]
    if adm:
        ctx.find("Third-party device administrator active", "medium", "high", "app-privilege", [f"active: {', '.join(adm)}"])
    for op, title, sev in (("REQUEST_INSTALL_PACKAGES", "Third-party apps allowed to install other apps", "low"), ("SYSTEM_ALERT_WINDOW", "Third-party apps allowed to draw overlays", "low"),
                           ("GET_USAGE_STATS", "Third-party apps with usage-stats access", "info"), ("MANAGE_EXTERNAL_STORAGE", "Third-party apps with all-files access", "info")):
        h = [p for p in app.get("appop_holders", {}).get(op, []) if p in third]
        if h:
            ctx.find(title, sev, "high", "app-privilege", [f"app-op {op}=allow: {', '.join(h)}"])
    both = [p for p in third if "a11y" in recs[p].get("capabilities", []) and "SYSTEM_ALERT_WINDOW" in recs[p].get("appop_special", [])]
    if both:
        ctx.find("App combines accessibility service and overlay permission", "medium", "medium", "app-privilege",
                 [f"declares accessibility service and holds overlay app-op: {', '.join(both)}"],
                 ["This combination is common in both legitimate tools and overlay-based malware; review the app."])
    dbg = [p for p in third if "DEBUGGABLE" in recs[p].get("flags", [])]
    if dbg:
        ctx.find("Debuggable third-party apps", "medium", "high", "apps", [f"flag DEBUGGABLE on: {', '.join(dbg[:15])}"])
    side = [p for p in third if _norm_installer(recs[p].get("installer")) is None]
    if side:
        ctx.find("Third-party apps without a store installer", "info", "medium", "apps", [f"installer is null/none/shell for {len(side)} app(s): {', '.join(sorted(side)[:15])}"],
                 ["Suggests sideloading or adb install; also normal for pre-loaded or developer builds."])
    smsapps = [p for p in third if SMS_CALL_PERMS & {x.rsplit('.', 1)[-1] for x in recs[p].get("granted", [])}]
    if smsapps:
        ctx.find("Third-party apps hold SMS/call-log permissions", "low", "high", "apps", [f"granted: {', '.join(sorted(smsapps)[:15])}"])
    bg = [p for p in third if any(x.endswith("ACCESS_BACKGROUND_LOCATION") for x in recs[p].get("granted", []))]
    if bg:
        ctx.find("Third-party apps granted background location", "low", "high", "apps", [", ".join(sorted(bg)[:15])])
    old = [p for p in third if str(recs[p].get("target_sdk") or "99").isdigit() and int(recs[p]["target_sdk"]) < 28]
    if old:
        ctx.find("Apps targeting old SDK levels", "low", "high", "apps", [f"targetSdk < 28: {', '.join(sorted(old)[:15])}"])
    exposed = [s for s in ctx.sockets if s["state"] == "LISTEN" and not s["local"].startswith(("127.", "::1"))]
    if exposed:
        ctx.find("Sockets listening on non-loopback addresses", "info", "high", "network",
                 [f"{len(exposed)} listening socket(s): " + ", ".join(sorted({f"{s['local']} ({s['owner']})" for s in exposed})[:12])], [], ctx.evidence("connectivity"))
    if any(s["local"].endswith(":5555") for s in exposed):
        ctx.find("Listener on TCP 5555 (ADB over network)", "medium", "high", "network", ["a socket listens on :5555"])
    if ctx.data.get("network", {}).get("tunnels"):
        ctx.find("VPN/tunnel interfaces present", "info", "high", "network", [f"interfaces: {', '.join(ctx.data['network']['tunnels'])}"],
                 ["Interface names only suggest a tunnel; they do not identify which app owns it."])
    if sec.get("hosts_entries"):
        ctx.find("Non-default /system/etc/hosts entries", "medium", "high", "network", [f"{len(sec['hosts_entries'])} entries"] + sec["hosts_entries"][:5], [], ctx.evidence("hosts"))
    anr = ctx.data.get("logs", {}).get("events", {}).get("anr", [])
    crashes = ctx.data.get("logs", {}).get("crashes", [])
    if crashes or anr:
        ctx.find("Recent crashes/ANRs in logs", "info", "high", "stability", [f"{len(crashes)} FATAL EXCEPTION record(s), {len(anr)} am_anr event(s) in the collected buffers"])
    for pkg, a in (ctx.data.get("apk_analysis") or {}).items():
        if a.get("exported_unprotected"):
            ctx.find(f"{pkg}: exported components without permission", "low", "medium", "apk", [f"{len(a['exported_unprotected'])} exported component(s) in the manifest"],
                     ["Exposure depends on what each component does; manual review required."])
    # collection coverage
    bad = [m for m in ctx.adb.log if m["status"] in (DENIED, UNSUPPORTED, TIMEOUT, FAILED)]
    if bad:
        from collections import Counter
        c = Counter(m["status"] for m in bad)
        ctx.find("Some data could not be collected", "info", "high", "coverage", [f"{c[s]} command(s) {s}" for s in c], ["See the command inventory for each command and the reason."])
