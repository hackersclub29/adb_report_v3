# Feature coverage matrix (adb_report v3.0)

Legend: **C** = collected when the shell is permitted to read it, **P** = partially (depends on OS build/permissions), **H** = host-side only (needs APK pull + tools).
"Min profile" is where it starts running; `--modules`/flags can enable anything on any profile.

| Area | What is collected | Module | Min profile | Notes / typical limits |
|---|---|---|---|---|
| Device identity, build, OS/API | all `getprop`, build/ID/fingerprint, patch levels, API/launch/vendor API, A/B, Treble, timezone, uptime | identity, build_config | quick | C |
| Kernel | `uname`, `/proc/version`, cmdline, modules, hardening sysctls, `/proc/config.gz` security keys | boot_security | quick/deep | config.gz often unreadable (P) |
| Boot / verified boot / bootloader | `ro.boot.*`, vbmeta, flash lock, dm-verity, crypto state | boot_security | quick | C from properties |
| SELinux | `getenforce`, sysfs enforce/policyvers, shell context | boot_security | quick | policy files unreadable |
| CPU / GPU / SoC / RAM | cpuinfo, microarchitecture decode, features, GLES renderer, meminfo, PSI, vmstat, `dumpsys meminfo`, frequencies/governors | hardware | quick | PSI/vmstat depend on kernel |
| Storage / partitions / mounts / FS | df, mounts, mountinfo, partitions, filesystems, by-name, sm volumes, diskstats | storage | quick | by-name usually denied (P) |
| Battery / charging / thermal | `dumpsys battery`, all power_supply nodes, thermal zones, cooling, thermalservice HAL | power | quick | sysfs nodes vary |
| Sensors / display / features / libraries | sensorservice, display modes/refresh, `pm list features/libraries` | hardware | quick | C |
| Users / accounts | `pm list users`, current user, `dumpsys account` | accounts | quick | C |
| Applications (all users) | packages per user, system/3rd-party/enabled/disabled, UIDs, APK base+splits, versions, installer/initiating installer, install/update times, min/target SDK, flags, signer hash, ABI, partition, APEX, uninstalled-with-data | packages | quick | per-user detail needs `--users all` (deep default) |
| Permissions | requested/granted/denied, runtime flags, per-user, catalog with groups and protection levels | packages | quick/deep | catalog deep |
| App-ops / roles | per-package `cmd appops get`, special-op holders, role holders (dynamic) | app_security | quick | all packages in exhaustive |
| Components / intent handlers | resolver-table components, actions, categories, authorities; capability queries (a11y, notification listeners, admins, VPN, IME, autofill, call-screening, SMS/boot receivers…) | packages, app_security | quick | **exported flag & non-filtered components need APK analysis (H)** |
| Overlays / usage access / install privilege / debug flags | `cmd overlay list`, appop holders, DEBUGGABLE/TEST_ONLY/ALLOW_BACKUP/CLEARTEXT flags | app_security | quick | C |
| APK hashes | device-side SHA-256 (3rd-party; all in exhaustive), host SHA-256 on pull | packages, apk_extract | deep(flag)/exhaustive | |
| Signing certificates | dumpsys signature hash (C); full cert digests via apksigner (H) | packages, apk_analysis | quick / exhaustive | |
| Manifest security attributes | exported/permission/authorities/cleartext/debuggable/network-security-config | apk_analysis | exhaustive (`--analyze-apks`) | H; needs apkanalyzer or apktool |
| Decompile / MobSF | JADX URL scan (heuristic), MobSF upload/scan/report | apk_analysis | flags | H |
| System services | dynamic `dumpsys -l`, `service list`, `cmd -l`; curated dumps (deep) or **every** service (exhaustive); raw preserved | services | deep | some services denied/time out (recorded) |
| Processes / runtime | ps (UID-attributed), top, cpuinfo, alarms, jobs, notifications, usagestats, procstats, exit-info (ANR/crash/kill reasons), DropBox, batterystats | runtime, services | quick/deep | exit-info Android 11+ |
| Network | IPv4/IPv6 interfaces, DNS, routes (all tables), rules, neighbours, tunnels, TCP/UDP/raw/UNIX sockets with UID, ss/netstat, per-UID accounting, proxy, private DNS, Wi-Fi state, saved-network metadata, bonded Bluetooth, telephony registry, connectivity dumps | network | quick | no passive-only probes; Wi-Fi passwords never accessible |
| Logs | all logcat buffers (discovered), event log (am_anr/am_crash/…), crash, radio, kernel buffer, dmesg, pstore, stats; parsed with timestamps/pid/tid/tag | logs | deep | dmesg/last_kmsg usually denied |
| Bugreport | `adb bugreport` + zip member inventory + SHA-256 | bugreport | exhaustive | device writes its own temp archive |
| Shared storage | recursive index (path/type/size/mtime/mode/owner), optional SHA-256, explicit denied paths, CSV artifact | storage_index | exhaustive / `--storage-index` | Scoped storage restrictions recorded, never faked |
| Correlation | package↔UID↔process↔socket↔permission↔capability↔accounting↔exits | correlation | quick | UID-level only |
| Findings | severity + confidence, observed facts vs heuristics, evidence command IDs | findings | always | |
| Baseline | diff vs previous `report.json` (packages, perms, props, settings, sockets, accounts, findings) | `--baseline` | any | |
| Inventory & manifest | every command with status (ok/empty/unsupported/denied/timeout/failed/blocked), exit code, duration, raw file; artifact SHA-256 manifest | always | | |

## Explicitly unavailable without root / privileged access
IMEI/IMSI/ICCID/phone number, other apps' private data, saved Wi-Fi passwords, keystore, `/data/anr`, `/data/tombstones`, `/proc/kmsg` (never read - it blocks), most `/data/misc`.
