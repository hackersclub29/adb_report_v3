"""Optional APK extraction and host-side analysis (apksigner, apkanalyzer, apktool, JADX, MobSF)."""
from __future__ import annotations

import json
import os
import posixpath
import re
import shutil
import subprocess
import urllib.request
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path

from . import parsers as P
from .collect_extra import _sha256_file
from .model import Ctx, table, details, fence, or_na, fmt_bytes

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"
URL_RE = re.compile(r"https?://[\w\-.~:/?#\[\]@!$&'()*+,;=%]{6,200}")


def find_tool(name: str, override: str | None = None) -> str | None:
    cand = override or os.environ.get(f"ADBR_{name.upper()}")
    if cand:
        return shutil.which(cand) or (cand if Path(cand).is_file() else None)
    return shutil.which(name)


def run_host(argv: list[str], timeout: int) -> tuple[int, str, str]:
    try:
        p = subprocess.run(argv, capture_output=True, timeout=timeout, stdin=subprocess.DEVNULL)
        return p.returncode, p.stdout.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace")
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except OSError as e:
        return 127, "", str(e)


def _a(el: ET.Element, name: str):
    return el.get(ANDROID_NS + name) if el.get(ANDROID_NS + name) is not None else el.get(name)


def parse_manifest_xml(xml_text: str) -> dict:
    """Manifest-declared security attributes. Exported default follows pre-Android-12 semantics (filters => exported)."""
    root = ET.fromstring(xml_text)
    out = {"package": root.get("package"), "uses_sdk": {}, "permissions": [], "declared_permissions": [], "application": {}, "components": {}}
    sdk = root.find("uses-sdk")
    if sdk is not None:
        out["uses_sdk"] = {"min": _a(sdk, "minSdkVersion"), "target": _a(sdk, "targetSdkVersion")}
    out["permissions"] = [_a(e, "name") for e in root.findall("uses-permission")] + [_a(e, "name") for e in root.findall("uses-permission-sdk-23")]
    out["declared_permissions"] = [{"name": _a(e, "name"), "protection": _a(e, "protectionLevel")} for e in root.findall("permission")]
    app = root.find("application")
    if app is None:
        return out
    out["application"] = {k: _a(app, a) for k, a in (("debuggable", "debuggable"), ("allow_backup", "allowBackup"), ("cleartext", "usesCleartextTraffic"),
                                                    ("network_security_config", "networkSecurityConfig"), ("test_only", "testOnly"),
                                                    ("extract_native_libs", "extractNativeLibs"), ("data_extraction_rules", "dataExtractionRules"))}
    for kind in ("activity", "activity-alias", "service", "receiver", "provider"):
        for el in app.findall(kind):
            filters = el.findall("intent-filter")
            exp = _a(el, "exported")
            c = {"name": _a(el, "name"), "exported": (exp == "true") if exp is not None else bool(filters), "exported_implicit": exp is None,
                 "permission": _a(el, "permission"), "actions": sorted({_a(a, "name") for f in filters for a in f.findall("action")}),
                 "authorities": _a(el, "authorities") if kind == "provider" else None,
                 "grant_uri_permissions": _a(el, "grantUriPermissions") if kind == "provider" else None}
            out["components"].setdefault(kind, []).append(c)
    return out


def parse_apksigner(text: str) -> dict:
    digests = re.findall(r"Signer #\d+ certificate SHA-256 digest: ([0-9a-f]+)", text)
    return {"verified": "Verifies" in text, "sha256_digests": digests, "dn": re.findall(r"certificate DN: (.+)", text),
            "schemes": {m[0]: m[1] == "true" for m in re.findall(r"Verified using (v[\d.]+) scheme[^:]*: (true|false)", text)}}


def _mobsf(url: str, key: str, apk: Path, timeout: int) -> dict:
    boundary = uuid.uuid4().hex
    data = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{apk.name}\"\r\nContent-Type: application/octet-stream\r\n\r\n").encode() \
        + apk.read_bytes() + f"\r\n--{boundary}--\r\n".encode()

    def call(path: str, body: bytes, ctype: str) -> dict:
        req = urllib.request.Request(url.rstrip("/") + path, data=body, headers={"Authorization": key, "Content-Type": ctype})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8", "replace"))
    up = call("/api/v1/upload", data, f"multipart/form-data; boundary={boundary}")
    form = f"hash={up['hash']}".encode()
    call("/api/v1/scan", form, "application/x-www-form-urlencoded")
    rep = call("/api/v1/report_json", form, "application/x-www-form-urlencoded")
    return {"hash": up["hash"], "security_score": rep.get("security_score") or rep.get("appsec", {}).get("security_score"),
            "keys": sorted(rep)[:30]}


def collect_apk_extract(ctx: Ctx) -> None:
    adb, args = ctx.adb, ctx.args
    dest = Path(args.pull_apks) if args.pull_apks else Path(ctx.out_dir or ".") / "apks"
    dest.mkdir(parents=True, exist_ok=True)
    scope = args.apk_scope
    pkgs = sorted(ctx.packages) if scope == "all" else sorted(ctx.third) if scope == "third" else [p for p in scope.split(",") if p in ctx.packages]
    rows = []
    ctx.progress(f"pulling APKs for {len(pkgs)} packages")
    for pkg in pkgs:
        if not P.PKG_RE.match(pkg):
            continue
        paths = ctx.packages[pkg].get("apk_paths") or P.parse_pm_path(adb.text(f"pm path {pkg}", label=f"pm-path-{pkg}"))
        pulled = []
        for p in paths:
            local = dest / pkg / posixpath.basename(p)
            local.parent.mkdir(parents=True, exist_ok=True)
            r = adb.run(["pull", p, str(local)], timeout=300, label=f"pull-{pkg}", save=False)
            if r.rc == 0 and local.is_file():
                h = _sha256_file(local)
                dev = ctx.packages[pkg].get("apk_sha256", {}).get(p)
                pulled.append({"device_path": p, "file": str(local), "bytes": local.stat().st_size, "sha256": h, "matches_device_hash": (dev == h) if dev else None})
                rows.append([pkg, local.name, fmt_bytes(local.stat().st_size), h, {True: "yes", False: "NO", None: "n/a"}[(dev == h) if dev else None]])
            else:
                rows.append([pkg, posixpath.basename(p), r.status, r.stderr.strip()[:60], "-"])
        ctx.packages[pkg]["pulled_apks"] = pulled
    ctx.data["apk_dir"] = str(dest)
    ctx.add("Pulled APKs", f"Saved under `{dest}` (one folder per package).\n\n" + table(["Package", "File", "Size", "SHA-256 (host)", "Matches device hash"], rows))


def collect_apk_analysis(ctx: Ctx) -> None:
    args = ctx.args
    tools = {n: find_tool(n, getattr(args, n, None)) for n in ("apksigner", "apkanalyzer", "apktool", "jadx")}
    out_root = Path(ctx.out_dir or ".") / "apk_analysis"
    results, rows = {}, []
    mobsf_on = bool(args.mobsf_url and args.mobsf_key)
    for pkg in sorted(ctx.packages):
        pulled = ctx.packages[pkg].get("pulled_apks") or []
        if not pulled:
            continue
        base = next((p for p in pulled if p["file"].endswith("base.apk")), pulled[0])
        apk = Path(base["file"])
        res: dict = {"apk": str(apk), "tools": {}}
        if tools["apksigner"]:
            rc, so, se = run_host([tools["apksigner"], "verify", "--print-certs", "-v", str(apk)], args.tool_timeout)
            res["signing"] = parse_apksigner(so + se)
            res["tools"]["apksigner"] = rc
        xml_text = None
        if tools["apkanalyzer"]:
            rc, so, _ = run_host([tools["apkanalyzer"], "manifest", "print", str(apk)], args.tool_timeout)
            res["tools"]["apkanalyzer"] = rc
            xml_text = so if rc == 0 and so.strip().startswith("<") else None
        if tools["apktool"] and (args.apktool_decode or not xml_text):
            d = out_root / pkg / "apktool"
            rc, _, _ = run_host([tools["apktool"], "d", "-f", "-o", str(d), str(apk)], args.tool_timeout * 3)
            res["tools"]["apktool"] = rc
            mf = d / "AndroidManifest.xml"
            if rc == 0 and mf.is_file():
                xml_text = xml_text or mf.read_text(encoding="utf-8", errors="replace")
        if xml_text:
            try:
                res["manifest"] = parse_manifest_xml(xml_text)
            except ET.ParseError as e:
                res["manifest_error"] = str(e)
        if tools["jadx"] and args.jadx_decompile:
            d = out_root / pkg / "jadx"
            rc, _, _ = run_host([tools["jadx"], "-d", str(d), "--no-res", str(apk)], args.tool_timeout * 6)
            res["tools"]["jadx"] = rc
            urls = set()
            for jf in list(d.rglob("*.java"))[:5000]:
                try:
                    urls |= set(URL_RE.findall(jf.read_text(encoding="utf-8", errors="ignore")))
                except OSError:
                    pass
            res["hardcoded_urls_heuristic"] = sorted(urls)[:200]
        if mobsf_on:
            try:
                res["mobsf"] = _mobsf(args.mobsf_url, args.mobsf_key, apk, args.tool_timeout * 4)
            except Exception as e:  # network/API errors are recorded, not fatal
                res["mobsf_error"] = f"{type(e).__name__}: {e}"
        mf = res.get("manifest")
        if mf:
            comps = [c for lst in mf["components"].values() for c in lst]
            exp = [c for c in comps if c["exported"] and not c["permission"]]
            res["exported_unprotected"] = [c["name"] for c in exp]
        # correlate with device observations
        rec = ctx.packages[pkg]
        if mf:
            res["correlation"] = {
                "manifest_perms_not_requested_on_device": sorted(set(mf["permissions"]) - set(rec.get("requested_perms", []))) if rec.get("requested_perms") else [],
                "debuggable_manifest_vs_device": [mf["application"].get("debuggable"), "DEBUGGABLE" in rec.get("flags", [])],
                "uid": rec.get("uid"), "listening_sockets": sum(1 for s in ctx.sockets if s["state"] == "LISTEN" and str(s["uid"]) == str(rec.get("uid")))}
        results[pkg] = res
        rows.append([pkg, ",".join(k for k, v in res["tools"].items() if v == 0) or "none", len(res.get("exported_unprotected", [])),
                     (res.get("manifest", {}).get("application", {}).get("cleartext") or "n/a"), len((res.get("signing") or {}).get("sha256_digests", []))])
        ctx.packages[pkg]["apk_analysis"] = res
    avail = ", ".join(f"{k}: {v or 'NOT FOUND'}" for k, v in tools.items())
    body = f"Host tools: {avail}; MobSF: {'configured' if mobsf_on else 'not configured'}.\n\n"
    body += table(["Package", "Tools that succeeded", "Exported w/o permission", "Cleartext attr", "Signer certs"], rows) if rows else "_No pulled APKs to analyse (run with apk_extract) or no tools found._"
    ctx.data["apk_analysis"] = results
    ctx.add("APK analysis (host-side)", body)
