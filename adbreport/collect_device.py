"""Device identity, boot/security, hardware, storage, power, users and accounts."""
from __future__ import annotations

import datetime as dt
import re

from . import parsers as P
from .adb import OK
from .model import Ctx, Spec, table, fence, details, or_na, fmt_kb, fmt_bytes, clip

ROOT_PACKAGES = ["com.topjohnwu.magisk", "io.github.vvb2060.magisk", "eu.chainfire.supersu", "com.noshufou.android.su",
                 "com.koushikdutta.superuser", "me.weishu.kernelsu", "com.thirdparty.superuser", "com.kingroot.kinguser"]
SU_PATHS = ["/system/bin/su", "/system/xbin/su", "/sbin/su", "/su/bin/su", "/vendor/bin/su", "/data/adb/magisk",
            "/data/local/bin/su", "/data/local/xbin/su", "/data/adb/ksu"]


def collect_settings(ctx: Ctx) -> None:
    """`settings list` for every namespace (read-only); falls back to targeted gets if list is unsupported."""
    adb = ctx.adb
    for ns in ("global", "secure", "system"):
        r = adb.shell(f"settings list {ns}", label=f"settings-{ns}", timeout=60)
        if r.ok:
            for ln in r.stdout.splitlines():
                k, eq, v = ln.partition("=")
                if eq:
                    ctx.settings[f"{ns}/{k}"] = v.strip()
    if not ctx.settings:
        pairs = [("global", "adb_enabled"), ("global", "development_settings_enabled"), ("global", "package_verifier_enable"),
                 ("global", "airplane_mode_on"), ("global", "private_dns_mode"), ("global", "http_proxy"),
                 ("secure", "enabled_accessibility_services"), ("secure", "enabled_notification_listeners"),
                 ("secure", "default_input_method"), ("secure", "autofill_service"), ("secure", "location_mode")]
        cmd = "; ".join(f'echo "{ns}/{k}=$(settings get {ns} {k} 2>/dev/null)"' for ns, k in pairs)
        for ln in adb.text(cmd, label="settings-targeted", timeout=90).splitlines():
            m = re.match(r"^(\w+/\w+)=(.*)$", ln)
            if m and m.group(2) != "null":
                ctx.settings[m.group(1)] = m.group(2).strip()
    ctx.data["settings"] = ctx.settings


def collect_identity(ctx: Ctx) -> None:
    adb, g = ctx.adb, ctx.props.get

    def first(*keys: str) -> str:
        return next((g(k) for k in keys if g(k)), "n/a")

    uname = adb.text("uname -a", label="uname")
    date = adb.text("date", label="date")
    up = adb.text("cat /proc/uptime", label="uptime").split()
    uptime = str(dt.timedelta(seconds=int(float(up[0])))) if up else "n/a"
    rows = [
        ["Device name", ctx.setting("global", "device_name")],
        ["Manufacturer / brand", f"{or_na(g('ro.product.manufacturer'))} / {or_na(g('ro.product.brand'))}"],
        ["Model", or_na(g("ro.product.model"))],
        ["Marketing name", first("ro.product.marketname", "ro.product.odm.marketname", "ro.product.vendor.marketname",
                                 "ro.product.system.marketname")],
        ["Device / product / board", f"{or_na(g('ro.product.device'))} / {or_na(g('ro.product.name'))} / {or_na(g('ro.product.board'))}"],
        ["Android release / codename", f"{or_na(g('ro.build.version.release'))} / {or_na(g('ro.build.version.codename'))}"],
        ["SDK (API) level / preview", f"{or_na(g('ro.build.version.sdk'))} / {or_na(g('ro.build.version.preview_sdk'))}"],
        ["Launch API / vendor API level", f"{or_na(g('ro.product.first_api_level'))} / {first('ro.vendor.api_level', 'ro.board.api_level')}"],
        ["Security patch / vendor patch", f"{or_na(g('ro.build.version.security_patch'))} / {or_na(g('ro.vendor.build.security_patch'))}"],
        ["Build ID / display / incremental", f"{or_na(g('ro.build.id'))} / {or_na(g('ro.build.display.id'))} / {or_na(g('ro.build.version.incremental'))}"],
        ["Build type / tags / user@host", f"{or_na(g('ro.build.type'))} / {or_na(g('ro.build.tags'))} / {or_na(g('ro.build.user'))}@{or_na(g('ro.build.host'))}"],
        ["Build date / UTC", f"{or_na(g('ro.build.date'))} / {or_na(g('ro.build.date.utc'))}"],
        ["Fingerprint", or_na(g("ro.build.fingerprint"))],
        ["Bootloader", first("ro.bootloader", "ro.boot.bootloader")],
        ["Baseband", or_na(g("gsm.version.baseband"))],
        ["Kernel", or_na(uname)],
        ["SoC / hardware / platform", f"{first('ro.soc.manufacturer')} {first('ro.soc.model')} / {or_na(g('ro.hardware'))} / {or_na(g('ro.board.platform'))}"],
        ["A/B / virtual A/B / slot", f"{or_na(g('ro.build.ab_update'))} / {or_na(g('ro.virtual_ab.enabled'))} / {or_na(g('ro.boot.slot_suffix'))}"],
        ["Treble / dynamic partitions / APEX", f"{or_na(g('ro.treble.enabled'))} / {or_na(g('ro.boot.dynamic_partitions'))} / {or_na(g('ro.apex.updatable'))}"],
        ["CPU ABIs", or_na(g("ro.product.cpu.abilist"))],
        ["Serial", or_na(g("ro.serialno") or ctx.adb.serial)],
        ["Locale / timezone", f"{or_na(g('persist.sys.locale') or g('ro.product.locale'))} / {or_na(g('persist.sys.timezone'))}"],
        ["Device time / uptime", f"{or_na(date)} / {uptime}"],
        ["ADB shell identity", or_na(ctx.caps.get("shell_identity"))],
    ]
    ctx.data["identity"] = {k: v for k, v in rows}
    ctx.data["kernel"] = {"uname": uname}
    ctx.add("Device overview", table(["Item", "Value"], rows))


def collect_build_config(ctx: Ctx) -> None:
    props = ctx.props
    groups: dict[str, int] = {}
    for k in props:
        groups[".".join(k.split(".")[:2])] = groups.get(".".join(k.split(".")[:2]), 0) + 1
    body = "**Property namespaces** (count)\n\n" + table(["Prefix", "Count"], sorted(([k, v] for k, v in groups.items()), key=lambda r: -r[1])[:40])
    lines = [f"{k} = {v}" for k, v in sorted(props.items())]
    body += "\n\n" + details(f"getprop ({len(props)} entries)", fence("\n".join(lines)))
    specs = [
        Spec("build_prop_system", "/system/build.prop", ["cat /system/build.prop"], 1, show=0),
        Spec("build_prop_vendor", "/vendor/build.prop", ["cat /vendor/build.prop"], 1, show=0),
        Spec("build_prop_product", "/product/etc/build.prop", ["cat /product/etc/build.prop"], 1, show=0),
        Spec("perm_xml", "Permission/feature XML names", ["ls /system/etc/permissions /vendor/etc/permissions /product/etc/permissions"], 1, show=15),
        Spec("init_rc", "init scripts (names)", ["ls /system/etc/init /vendor/etc/init"], 1, show=15),
        Spec("hosts", "/system/etc/hosts", ["cat /system/etc/hosts"], 0, show=20),
    ]
    items = ctx.run_specs(specs)
    body += "\n\n" + ctx.render_items(items, specs)
    ctx.data["props"] = props
    ctx.add("Build and system configuration", body)


def collect_boot_security(ctx: Ctx) -> None:
    adb, g = ctx.adb, ctx.props.get
    specs = [
        Spec("selinux_getenforce", "getenforce", ["getenforce"], 0, show=2),
        Spec("selinux_sysfs", "SELinux sysfs enforce", ["cat /sys/fs/selinux/enforce"], 0, show=2),
        Spec("selinux_policyvers", "SELinux policy version", ["cat /sys/fs/selinux/policyvers"], 0, show=2),
        Spec("cmdline", "/proc/cmdline", ["cat /proc/cmdline"], 0, parser=P.parse_cmdline, show=10),
        Spec("proc_version", "/proc/version", ["cat /proc/version"], 0, show=3),
        Spec("modules", "Loaded kernel modules", ["cat /proc/modules"], 1, show=15),
        Spec("kernel_sysctl", "Kernel hardening sysctls", [
            'for f in kptr_restrict perf_event_paranoid dmesg_restrict randomize_va_space modules_disabled '
            'unprivileged_bpf_disabled kexec_load_disabled yama/ptrace_scope; do echo "$f=$(cat /proc/sys/kernel/$f 2>/dev/null)"; done'],
             0, parser=P.parse_kv_lines, show=12),
        Spec("kernel_config", "Kernel config (/proc/config.gz)", ["zcat /proc/config.gz", "gzip -dc /proc/config.gz"], 1,
             parser=P.parse_kernel_config, show=0),
        Spec("su_paths", "su / root-manager paths", ["for p in " + " ".join(SU_PATHS) + "; do [ -e $p ] && echo $p; done; true"], 0, show=5),
        Spec("user_cacerts", "User-installed CA certificates", ["ls /data/misc/user/0/cacerts-added"], 0, show=20),
        Spec("system_cacerts", "System CA certificate count", [
            "ls /apex/com.android.conscrypt/cacerts | wc -l", "ls /system/etc/security/cacerts | wc -l"], 1, show=2),
        Spec("device_policy", "Device policy (admins)", ["dumpsys device_policy"], 0, parser=P.parse_device_admins, show=0, timeout=60),
    ]
    items = {i.key: i for i in ctx.run_specs(specs)}
    vb = {k: v for k, v in ctx.props.items() if k.startswith(("ro.boot.", "ro.bootmode", "ro.bootimage", "ro.crypto.", "ro.oem_unlock", "sys.oem_unlock"))}
    selinux = items["selinux_getenforce"].text.strip() or {"1": "Enforcing", "0": "Permissive"}.get(items["selinux_sysfs"].text.strip(), "")
    st = ctx.setting
    hosts = [ln for ln in ctx.fetch("hosts").splitlines() if ln.strip() and not ln.strip().startswith("#")
             and not re.match(r"^(127\.0\.0\.1|::1)\s+(ip6-)?localhost", ln.strip())]
    su_hits = [x for x in items["su_paths"].text.splitlines() if x.strip()]
    tcp_port = g("service.adb.tcp.port") or g("persist.adb.tcp.port") or ""
    sysctl = items["kernel_sysctl"].parsed or {}
    rows = [
        ["SELinux mode (getenforce)", or_na(selinux)],
        ["Verified boot state", or_na(g("ro.boot.verifiedbootstate"))],
        ["vbmeta device state / AVB version", f"{or_na(g('ro.boot.vbmeta.device_state'))} / {or_na(g('ro.boot.avb_version'))}"],
        ["vbmeta digest / hash alg / size", f"{or_na(g('ro.boot.vbmeta.digest'))} / {or_na(g('ro.boot.vbmeta.hash_alg'))} / {or_na(g('ro.boot.vbmeta.size'))}"],
        ["Bootloader locked (ro.boot.flash.locked)", or_na(g("ro.boot.flash.locked"))],
        ["dm-verity mode", or_na(g("ro.boot.veritymode"))],
        ["OEM unlock supported / allowed", f"{or_na(g('ro.oem_unlock_supported'))} / {or_na(g('sys.oem_unlock_allowed'))}"],
        ["Encryption state / type", f"{or_na(g('ro.crypto.state'))} / {or_na(g('ro.crypto.type'))}"],
        ["Boot reason / mode", f"{or_na(g('ro.boot.bootreason'))} / {or_na(g('ro.bootmode'))}"],
        ["ro.secure / ro.debuggable / ro.adb.secure", f"{or_na(g('ro.secure'))} / {or_na(g('ro.debuggable'))} / {or_na(g('ro.adb.secure'))}"],
        ["USB debugging / wireless debugging", f"{st('global', 'adb_enabled')} / {st('global', 'adb_wifi_enabled')}"],
        ["ADB TCP port (props)", tcp_port or "n/a"],
        ["Developer options", st("global", "development_settings_enabled")],
        ["Package verifier / verify adb installs", f"{st('global', 'package_verifier_enable')} / {st('global', 'verifier_verify_adb_installs')}"],
        ["Legacy unknown-sources flag", st("secure", "install_non_market_apps")],
        ["Mock locations (ro.allow.mock.location)", or_na(g("ro.allow.mock.location"))],
        ["Kernel hardening sysctls", ", ".join(f"{k}={v}" for k, v in sysctl.items()) or "n/a"],
        ["Kernel config keys readable", len(items["kernel_config"].parsed or {})],
        ["Loaded kernel modules", len(items["modules"].text.splitlines())],
        ["su / root paths found", ", ".join(su_hits) or "none"],
        ["Non-default hosts entries", len(hosts)],
        ["System CA count", or_na(items["system_cacerts"].text.strip())],
        ["User CA directory", items["user_cacerts"].status],
    ]
    body = table(["Check", "Value"], rows)
    body += "\n\n" + details("Boot/crypto/verified-boot properties", table(["Property", "Value"], [[k, v] for k, v in sorted(vb.items())]))
    body += "\n\n" + ctx.render_items(list(items.values()), specs)
    admins = items["device_policy"].parsed or []
    ctx.data["security"] = {"selinux": selinux, "verified_boot": {k: v for k, v in vb.items()}, "su_paths": su_hits, "hosts_entries": hosts,
                            "kernel_sysctl": sysctl, "kernel_config_security": {k: v for k, v in (items["kernel_config"].parsed or {}).items()
                                                                               if re.search(r"SELINUX|RANDOMIZE|STACKPROTECTOR|CFI|SHADOW_CALL|HARDENED|FORTIFY|BPF_JIT|SECCOMP|KASLR|INIT_STACK", k)},
                            "device_admins": admins, "tcp_port": tcp_port, "cmdline": items["cmdline"].parsed or {}}
    ctx.add("Boot, verified boot and security posture", body)


def collect_hardware(ctx: Ctx) -> None:
    adb = ctx.adb
    specs = [
        Spec("cpuinfo", "/proc/cpuinfo", ["cat /proc/cpuinfo"], 0, parser=P.parse_cpuinfo, show=0),
        Spec("meminfo", "/proc/meminfo", ["cat /proc/meminfo"], 0, parser=P.parse_meminfo, show=0),
        Spec("vmstat", "/proc/vmstat", ["cat /proc/vmstat"], 1, parser=P.parse_vmstat, show=0),
        Spec("psi_memory", "Memory pressure (PSI)", ["cat /proc/pressure/memory"], 0, parser=P.parse_psi, show=3),
        Spec("psi_cpu", "CPU pressure (PSI)", ["cat /proc/pressure/cpu"], 1, parser=P.parse_psi, show=3),
        Spec("psi_io", "I/O pressure (PSI)", ["cat /proc/pressure/io"], 1, parser=P.parse_psi, show=3),
        Spec("dumpsys_meminfo", "dumpsys meminfo", ["dumpsys meminfo"], 1, timeout=90, parser=P.parse_dumpsys_meminfo, show=0),
        Spec("cpu_freq", "CPU frequencies / governors", [
            'for c in /sys/devices/system/cpu/cpu[0-9]*; do echo "$(basename $c)|$(cat $c/cpufreq/cpuinfo_max_freq 2>/dev/null)|'
            '$(cat $c/cpufreq/scaling_cur_freq 2>/dev/null)|$(cat $c/cpufreq/cpuinfo_min_freq 2>/dev/null)|'
            '$(cat $c/cpufreq/scaling_governor 2>/dev/null)"; done'], 0, parser=P.parse_cpu_freq, show=0),
        Spec("surfaceflinger", "SurfaceFlinger (GPU/display)", ["dumpsys SurfaceFlinger"], 1, timeout=60, show=0),
        Spec("display", "dumpsys display", ["dumpsys display"], 0, timeout=60, parser=P.parse_display, show=0),
        Spec("wm_size", "wm size", ["wm size"], 0, show=3),
        Spec("wm_density", "wm density", ["wm density"], 0, show=3),
        Spec("sensors", "dumpsys sensorservice", ["dumpsys sensorservice"], 0, timeout=60, parser=P.parse_sensors, show=0),
        Spec("features", "System features", ["pm list features"], 0, parser=P.parse_pm_features, show=0),
        Spec("libraries", "Shared libraries", ["pm list libraries"], 0, parser=P.parse_pm_libraries, show=0),
        Spec("gpu_props", "GPU/graphics properties", ['for k in ro.hardware.egl ro.hardware.vulkan ro.opengles.version ro.surface_flinger.max_frame_buffer_acquired_buffers; do echo "$k=$(getprop $k)"; done'],
             0, parser=P.parse_kv_lines, show=6),
    ]
    items = {i.key: i for i in ctx.run_specs(specs)}
    cpu = items["cpuinfo"].parsed or {}
    mem = items["meminfo"].parsed or {}
    g = ctx.props.get
    soc = " ".join(x for x in (g("ro.soc.manufacturer"), g("ro.soc.model")) if x) or cpu.get("hardware") or g("ro.board.platform") or g("ro.hardware")
    gles = re.search(r"GLES:\s*(.+)", ctx.fetch("surfaceflinger"))
    disp = items["display"].parsed or {}
    mi = items["dumpsys_meminfo"].parsed or {}
    freq = items["cpu_freq"].parsed or []
    sensors = items["sensors"].parsed or []
    kb = lambda k: fmt_kb(mem[k]) if k in mem else "n/a"
    feats = set(cpu.get("features", []))
    rows = [
        ["SoC", or_na(soc)],
        ["Platform / board / hardware", f"{or_na(g('ro.board.platform'))} / {or_na(g('ro.product.board'))} / {or_na(g('ro.hardware'))}"],
        ["CPU cores", cpu.get("cores") or "n/a"],
        ["CPU microarchitectures", ", ".join(f"{n}x {k}" for k, n in sorted(cpu.get("microarchitectures", {}).items(), key=lambda kv: -kv[1])) or "n/a"],
        ["Crypto/ISA features", ", ".join(x for x in ("aes", "sha1", "sha2", "sha3", "sha512", "pmull", "crc32", "atomics", "sve", "sve2", "bti", "mte") if x in feats) or "n/a"],
        ["GPU (GLES renderer)", gles.group(1).strip() if gles else "n/a"],
        ["Graphics props", ", ".join(f"{k}={v}" for k, v in (items['gpu_props'].parsed or {}).items() if v) or "n/a"],
        ["RAM total / available / free", f"{kb('MemTotal')} / {kb('MemAvailable')} / {kb('MemFree')}"],
        ["Cached / buffers / shmem", f"{kb('Cached')} / {kb('Buffers')} / {kb('Shmem')}"],
        ["Swap total / free", f"{kb('SwapTotal')} / {kb('SwapFree')}"],
        ["Memory status (dumpsys meminfo)", f"{mi.get('memory_status', 'n/a')}; lost RAM {fmt_kb(mi['lost_ram_kb']) if 'lost_ram_kb' in mi else 'n/a'}"],
        ["Memory pressure avg10 some/full", f"{(items['psi_memory'].parsed or {}).get('some', {}).get('avg10', 'n/a')} / {(items['psi_memory'].parsed or {}).get('full', {}).get('avg10', 'n/a')}"],
        ["Display size / density", f"{or_na(items['wm_size'].text.replace(chr(10), '; '))} / {or_na(items['wm_density'].text.replace(chr(10), '; '))}"],
        ["Refresh rates (Hz)", ", ".join(f"{x:g}" for x in disp.get("refresh_rates", [])) or "n/a"],
        ["Sensors / features / shared libraries", f"{len(sensors)} / {len(items['features'].parsed or [])} / {len(items['libraries'].parsed or [])}"],
    ]
    body = table(["Item", "Value"], rows)
    if freq:
        body += "\n\n**CPU frequencies and governors**\n\n" + table(["Core", "Max MHz", "Current MHz", "Min MHz", "Governor"], [
            [f["cpu"], f["max_khz"] // 1000 if f["max_khz"] > 0 else "n/a", f["cur_khz"] // 1000 if f["cur_khz"] > 0 else "n/a",
             f["min_khz"] // 1000 if f["min_khz"] > 0 else "n/a", f["governor"] or "n/a"] for f in freq])
    if disp.get("modes"):
        body += "\n\n" + details("Display modes", table(["Width", "Height", "FPS"], [[m["width"], m["height"], m["fps"]] for m in disp["modes"]]))
    if sensors:
        body += "\n\n" + details(f"Sensors ({len(sensors)})", table(["Sensor", "Vendor", "Type"], [[s["name"], s["vendor"], s["type"]] for s in sensors]))
    if mi.get("top_pss"):
        body += "\n\n" + details("Top processes by PSS", table(["Process", "PID", "PSS"], [[t["process"], t["pid"], fmt_kb(t["pss_kb"])] for t in mi["top_pss"][:20]]))
    body += "\n\n" + details("Features", fence("\n".join(items["features"].parsed or []) or "unavailable"))
    body += "\n\n" + details("Shared libraries", fence("\n".join(items["libraries"].parsed or []) or "unavailable"))
    body += "\n\n" + ctx.render_items(list(items.values()), specs)
    ctx.data["hardware"] = {"soc": soc, "cpu": cpu, "memory_kb": mem, "memory_pressure": {k: items[k].parsed for k in ("psi_memory", "psi_cpu", "psi_io")},
                            "vmstat": items["vmstat"].parsed, "dumpsys_meminfo": mi, "cpu_frequencies": freq, "gpu": gles.group(1).strip() if gles else None,
                            "display": disp, "sensors": sensors, "features": items["features"].parsed, "libraries": items["libraries"].parsed}
    ctx.add("Hardware, CPU, GPU, memory, display and sensors", body)


def collect_storage_info(ctx: Ctx) -> None:
    specs = [
        Spec("df", "df", ["df -k", "df"], 0, parser=P.parse_df, show=40),
        Spec("mounts", "/proc/mounts", ["cat /proc/mounts"], 0, parser=P.parse_mounts, show=0),
        Spec("mountinfo", "/proc/self/mountinfo", ["cat /proc/self/mountinfo"], 1, show=0),
        Spec("partitions", "/proc/partitions", ["cat /proc/partitions"], 0, parser=P.parse_partitions, show=30),
        Spec("filesystems", "/proc/filesystems", ["cat /proc/filesystems"], 0, parser=P.parse_filesystems, show=0),
        Spec("by_name", "Partition names (/dev/block/by-name)", ["ls -l /dev/block/by-name", "ls -l /dev/block/platform/*/by-name"], 1, show=40),
        Spec("swaps", "/proc/swaps", ["cat /proc/swaps"], 1, show=5),
        Spec("diskstats_proc", "/proc/diskstats", ["cat /proc/diskstats"], 1, show=0),
        Spec("sm_volumes", "Storage volumes (sm)", ["sm list-volumes all"], 1, show=20),
        Spec("sm_disks", "Storage disks (sm)", ["sm list-disks"], 1, show=10),
        Spec("dumpsys_mount", "dumpsys mount", ["dumpsys mount"], 1, timeout=60, show=0),
        Spec("dumpsys_diskstats", "dumpsys diskstats", ["dumpsys diskstats"], 1, timeout=90, parser=P.parse_diskstats, show=0),
    ]
    items = {i.key: i for i in ctx.run_specs(specs)}
    mounts = items["mounts"].parsed or []
    body = ""
    if items["df"].parsed:
        body += "**Filesystem usage**\n\n" + table(["Filesystem", "Size", "Used", "Avail", "Use%", "Mount"], [
            [r["filesystem"], fmt_kb(r["size_kb"]), fmt_kb(r["used_kb"]), fmt_kb(r["avail_kb"]), r["use_pct"], r["mount"]] for r in items["df"].parsed])
    if mounts:
        body += "\n\n" + details(f"Mounts ({len(mounts)})", table(["Device", "Mount", "FS", "Options"], [[m["device"], m["mount"], m["fstype"], m["options"]] for m in mounts]))
    ds = items["dumpsys_diskstats"].parsed or {"apps": [], "summary": {}}
    if ds["summary"]:
        body += "\n\n**Disk stats**\n\n" + table(["Metric", "Value"], [[k, v] for k, v in list(ds["summary"].items())[:25]])
    if ds["apps"]:
        top = sorted(ds["apps"], key=lambda a: -(a["app_bytes"] + a["data_bytes"] + a["cache_bytes"]))[:25]
        body += "\n\n" + details("Largest apps by storage", table(["Package", "App", "Data", "Cache", "Total"], [
            [a["package"], fmt_bytes(a["app_bytes"]), fmt_bytes(a["data_bytes"]), fmt_bytes(a["cache_bytes"]),
             fmt_bytes(a["app_bytes"] + a["data_bytes"] + a["cache_bytes"])] for a in top]))
    body += "\n\n" + ctx.render_items(list(items.values()), specs)
    ctx.data["storage"] = {"df": items["df"].parsed, "mounts": mounts, "partitions": items["partitions"].parsed,
                           "filesystems": items["filesystems"].parsed, "diskstats": ds}
    ctx.add("Storage, partitions, mounts and filesystems", body)


def collect_power(ctx: Ctx) -> None:
    specs = [
        Spec("battery", "dumpsys battery", ["dumpsys battery"], 0, parser=P.parse_battery, show=40),
        Spec("power_supply", "power_supply sysfs", [
            'for s in /sys/class/power_supply/*; do echo "== $(basename $s)"; for f in type status present online capacity health '
            'voltage_now current_now temp cycle_count charge_full charge_full_design charge_counter technology charge_type; do '
            'v=$(cat $s/$f 2>/dev/null); [ -n "$v" ] && echo "$f=$v"; done; done; true'], 0, parser=P.parse_power_supply, show=0),
        Spec("thermal_sysfs", "Thermal zones (sysfs)", [
            'for z in /sys/class/thermal/thermal_zone*; do echo "$(cat $z/type 2>/dev/null)|$(cat $z/temp 2>/dev/null)"; done'],
             0, parser=P.parse_thermal_sysfs, show=0),
        Spec("cooling", "Cooling devices", ['for z in /sys/class/thermal/cooling_device*; do echo "$(cat $z/type 2>/dev/null)|$(cat $z/cur_state 2>/dev/null)/$(cat $z/max_state 2>/dev/null)"; done'], 1, show=30),
        Spec("thermalservice", "dumpsys thermalservice", ["dumpsys thermalservice"], 1, timeout=60, parser=P.parse_thermalservice, show=0),
    ]
    items = {i.key: i for i in ctx.run_specs(specs)}
    bat = items["battery"].parsed or {}
    ps = items["power_supply"].parsed or {}
    bsys = ps.get("battery") or next((v for v in ps.values() if v.get("type", "").lower() == "battery"), {})
    rows = [["Level", f"{bat.get('level', 'n/a')}%"], ["Status / health", f"{bat.get('status_text', 'n/a')} / {bat.get('health_text', 'n/a')}"],
            ["Temperature", f"{bat['temperature_c']:.1f} C" if "temperature_c" in bat else "n/a"],
            ["Charging sources", ", ".join(bat.get("power_sources", [])) or "battery"],
            ["Voltage (mV)", or_na(bat.get("voltage"))], ["Technology", or_na(bat.get("technology") or bsys.get("technology"))],
            ["Max charging current / voltage", f"{or_na(bat.get('Max charging current'))} / {or_na(bat.get('Max charging voltage'))}"],
            ["Cycle count (sysfs)", or_na(bsys.get("cycle_count"))]]
    try:
        rows.append(["Capacity vs design (sysfs)", f"{int(bsys['charge_full']) * 100 / int(bsys['charge_full_design']):.0f}%"])
    except (KeyError, ValueError, ZeroDivisionError):
        pass
    body = table(["Item", "Value"], rows)
    if ps:
        body += "\n\n**Power supplies (sysfs)**\n\n" + table(["Supply", "Type", "Status", "Online", "Capacity"], [
            [n, v.get("type", ""), v.get("status", ""), v.get("online", ""), v.get("capacity", "")] for n, v in ps.items()])
    tz = items["thermal_sysfs"].parsed or []
    if tz:
        body += "\n\n**Thermal zones**\n\n" + table(["Zone", "Temp (C)"], [[t["zone"], f"{t['temp_c']:.1f}"] for t in tz[:60]])
    ts = items["thermalservice"].parsed or []
    if ts:
        body += "\n\n**Thermal HAL temperatures**\n\n" + table(["Name", "Type", "Value (C)"], [[t["name"], t["type"], t["value_c"]] for t in ts])
    body += "\n\n" + ctx.render_items(list(items.values()), specs)
    ctx.data["power"] = {"battery": bat, "power_supply": ps, "thermal_zones": tz, "thermal_hal": ts}
    ctx.add("Battery, charging and thermal", body)


def prepare_users(ctx: Ctx) -> None:
    adb = ctx.adb
    users = P.parse_pm_users(adb.text("pm list users", label="pm-list-users")) or [{"id": 0, "name": "(default)", "flags": "", "running": True}]
    cur = adb.text("am get-current-user", label="current-user").strip()
    ctx.users = users
    ctx.current_user = int(cur) if cur.isdigit() else users[0]["id"]
    ids = [u["id"] for u in users]
    sel = getattr(ctx.args, "users", None)
    if sel == "current" or (sel is None and ctx.level == 0):
        ctx.target_users = [ctx.current_user]
    elif sel in (None, "all"):
        ctx.target_users = ids
    else:
        want = [int(x) for x in str(sel).split(",") if x.strip().isdigit()]
        ctx.target_users = [i for i in ids if i in want] or [ctx.current_user]


def collect_users_accounts(ctx: Ctx) -> None:
    adb = ctx.adb
    specs = [
        Spec("max_users", "pm get-max-users", ["pm get-max-users"], 1, show=2),
        Spec("accounts", "dumpsys account", ["dumpsys account"], 0, timeout=60, parser=P.parse_accounts, show=0),
    ]
    items = {i.key: i for i in ctx.run_specs(specs)}
    accts = items["accounts"].parsed or []
    from collections import Counter
    body = "**Users**\n\n" + table(["Id", "Name", "Flags", "Running"], [[u["id"], u["name"], u["flags"], u["running"]] for u in ctx.users])
    body += "\n\n**Accounts by type**\n\n" + table(["Type", "Count"], [[k, v] for k, v in Counter(a["type"] for a in accts).most_common()])
    body += "\n\n" + details(f"All accounts ({len(accts)})", table(["Type", "Name"], [[a["type"], a["name"]] for a in accts]))
    body += "\n\n" + ctx.render_items(list(items.values()), specs)
    ctx.data["users"] = ctx.users
    ctx.data["accounts"] = accts
    ctx.add("Users, profiles and accounts", body)
