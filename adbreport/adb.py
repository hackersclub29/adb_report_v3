"""ADB transport: safe subprocess wrapper, result classification, read-only guard, command log."""
from __future__ import annotations

import datetime as dt
import os
import re
import shlex
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional, Sequence

OK, EMPTY, UNSUPPORTED, DENIED, TIMEOUT, FAILED, BLOCKED = (
    "ok", "empty", "unsupported", "denied", "timeout", "failed", "blocked")
STATUSES = (OK, EMPTY, UNSUPPORTED, DENIED, TIMEOUT, FAILED, BLOCKED)
BATCH_MARK = "@@ITEM@@"


class AdbError(RuntimeError):
    pass


class BlockedCommand(AdbError):
    pass


# --------------------------------------------------------------------------- #
# Filenames (Windows-safe)
# --------------------------------------------------------------------------- #
_WIN_RESERVED = {"con", "prn", "aux", "nul", *(f"com{i}" for i in range(1, 10)), *(f"lpt{i}" for i in range(1, 10))}


def safe_filename(text: str, maxlen: int = 60) -> str:
    s = re.sub(r"[^\w.-]+", "_", text, flags=re.ASCII).strip("._")[:maxlen].strip("._") or "x"
    if s.split(".")[0].lower() in _WIN_RESERVED:
        s = "_" + s
    return s


# --------------------------------------------------------------------------- #
# Classification
# --------------------------------------------------------------------------- #
DENIED_RE = re.compile(
    r"permission denied|permission denial|securityexception|operation not permitted|not permitted|"
    r"access denied|requires android\.permission|avc: +denied|must be root", re.I)
UNSUPPORTED_RE = re.compile(
    r"not found|no such file|no such service|can't find service|unknown command|unknown option|"
    r"unknown service|unrecognized|invalid option|bad argument|illegal option|inaccessible or not found|"
    r"not supported|not implemented|unknown subcommand|usage:|no service", re.I)
ERRLINE_RE = re.compile(
    r"(?im)^(exception occurred|java\.lang\.|error:|error type|error during|cmd: can't find|can't find service|"
    r"[^\n]*permission denial|[^\n]*securityexception|[^:\n]+: (?:not found|inaccessible or not found)|"
    r"unknown (?:command|option|service)|failure|usage:|[^\n]*: (?:permission denied|operation not permitted))")
TRANSPORT_RE = re.compile(r"device offline|error: closed|protocol fault|device .* not found|no devices/emulators|"
                          r"device unauthorized|more than one device", re.I)


def _err_kind(text: str) -> Optional[str]:
    if DENIED_RE.search(text):
        return DENIED
    if UNSUPPORTED_RE.search(text):
        return UNSUPPORTED
    return None


def classify(rc: int, out: str, err: str, timed_out: bool = False) -> tuple[str, bool]:
    """Return (status, partial). 'empty' = ran fine with no output; never conflated with failure."""
    if timed_out:
        return TIMEOUT, False
    has_out, e = bool(out.strip()), err.strip()
    if rc == 0:
        if not has_out:
            return (_err_kind(e) or EMPTY) if e else EMPTY, False
        if len(out) < 2000 and ERRLINE_RE.search(out):
            return _err_kind(out) or FAILED, False
        return OK, False
    if rc == 127:
        return UNSUPPORTED, False
    if has_out and not ERRLINE_RE.search(out[:2000]):
        return OK, True  # useful data despite non-zero exit (e.g. find hit a denied dir)
    return _err_kind(e + "\n" + out[:800]) or FAILED, False


# --------------------------------------------------------------------------- #
# Read-only guard: refuses anything that could change the device.
# --------------------------------------------------------------------------- #
_REDIR_OK = re.compile(r"\d*>\s*/dev/null|\d*>&\d|&>\s*/dev/null|<\s*/dev/null")
_SPLIT = re.compile(r"&&|\|\||[;|\n&()]")
_PREFIX = {"do", "then", "else", "elif", "if", "while", "until", "!", "{", "}", "time", "command"}
_WRAP = {"toybox", "busybox", "env", "nohup", "timeout", "nice", "ionice", "stdbuf"}
_BLOCK = {"rm", "rmdir", "mv", "cp", "dd", "mkdir", "touch", "chmod", "chown", "chgrp", "ln", "setprop", "resetprop",
          "reboot", "shutdown", "kill", "killall", "pkill", "svc", "input", "tee", "truncate", "umount", "sh", "bash",
          "su", "run-as", "eval", "source", "exec", "install", "monkey", "screencap", "screenrecord", "bmgr",
          "locksettings", "dpm", "ndc", "stop", "start", "setenforce", "insmod", "rmmod", "mkfs", "fsck", "wipe",
          "restorecon", "chcon", "mknod", "swapoff", "swapon", "wpa_cli", "sync"}
_MUT = re.compile(r"^(set|grant|revoke|reset|install|uninstall|clear|disable|enable|force|kill|write|add|remove|delete|"
                  r"suspend|unsuspend|hide|unhide|reboot|start|stop|put|send|trigger|connect|disconnect|forget|save|"
                  r"restart|override|reload|update|create|cancel|bypass|compile)(-|$)", re.I)
_DUMPSYS_BLOCK = {"--reset", "--enable", "--disable", "--write", "--clear", "--unplug", "force-idle", "unforce",
                  "step", "enable", "disable", "--set", "set", "--restore", "reset", "--stop-testing", "--start-testing"}
_LOGCAT_BLOCK = {"-c", "-C", "--clear", "-G", "--buffer-size", "-f", "-r", "-n", "-P", "--prune", "-p"}
_EXEC_OK = {"stat", "sha256sum", "sha1sum", "md5sum", "ls", "wc", "file", "cat", "du", "basename", "readlink"}


def _first_sub(args: list[str]) -> str:
    skip = False
    for a in args:
        if skip:
            skip = False
            continue
        if a in ("--user", "-u"):
            skip = True
            continue
        if a.startswith("-"):
            continue
        return a
    return ""


def _check_words(words: list[str]) -> Optional[str]:
    i = 0
    while i < len(words):
        w = words[i]
        if w in _PREFIX or re.match(r"^\w+=", w):
            i += 1
        elif w in _WRAP:
            i += 1
            if w == "timeout" and i < len(words) and re.match(r"^[\d.]+[smhd]?$", words[i]):
                i += 1
        else:
            break
    if i >= len(words):
        return None
    cmd, args = os.path.basename(words[i]), words[i + 1:]
    if cmd in _BLOCK:
        return f"'{cmd}' can modify the device"
    sub = _first_sub(args)
    if cmd == "mount" and args:
        return "mount with arguments"
    if cmd == "settings" and sub not in ("get", "list"):
        return "settings subcommand is not get/list"
    if cmd == "pm" and not (sub.startswith(("list", "path", "dump", "query-", "resolve-", "get-", "has-feature",
                                           "check-", "is-")) and sub != "dump-profiles"):
        return f"pm {sub} is not read-only"
    if cmd == "cmd" and "-l" not in args[:1] and any(_MUT.match(a) for a in args[1:]):
        return "cmd mutating verb"
    if cmd == "am" and not (sub.startswith(("get-", "is-")) or sub in ("stack", "version")):
        return f"am {sub} is not read-only"
    if cmd == "dumpsys" and any(a in _DUMPSYS_BLOCK for a in args):
        return "dumpsys state-changing argument"
    if cmd == "content" and sub != "query":
        return "content provider write"
    if cmd == "wm" and args and not (len(args) == 1 and args[0] in ("size", "density")):
        return "wm setter"
    if cmd == "wm" and not args:
        return "wm without args"
    if cmd == "logcat" and any(a in _LOGCAT_BLOCK for a in args):
        return "logcat flag that clears/changes buffers"
    if cmd == "dmesg" and any(a in ("-c", "-C", "-n", "--clear") for a in args):
        return "dmesg clear"
    if cmd == "sm" and not sub.startswith(("list-", "has-", "get-")):
        return "sm mutating subcommand"
    if cmd == "ime" and sub != "list":
        return "ime mutating subcommand"
    if cmd == "service" and sub not in ("list", "check"):
        return "service call"
    if cmd in ("iptables", "ip6tables") and any(a in ("-A", "-I", "-D", "-F", "-X", "-P", "-N", "-R", "-Z", "-E") for a in args):
        return "iptables rule change"
    if cmd == "ip" and any(a in ("add", "del", "delete", "flush", "set", "change", "replace", "append", "prepend",
                                 "save", "restore", "exec", "monitor") for a in args):
        return "ip state change"
    if cmd == "ifconfig" and len([a for a in args if not a.startswith("-")]) > 1:
        return "ifconfig setter"
    if cmd == "sed" and any(a.startswith("-i") for a in args):
        return "sed -i"
    if cmd == "find":
        if any(a == "-delete" or a.startswith("-fprint") for a in args):
            return "find writes/deletes"
        for j, a in enumerate(args):
            if a in ("-exec", "-execdir", "-ok") and (j + 1 >= len(args) or os.path.basename(args[j + 1]) not in _EXEC_OK):
                return "find -exec of a non-read-only tool"
    return None


def check_read_only(cmd: str) -> None:
    """Raise BlockedCommand if the device shell command could modify the device."""
    stripped = _REDIR_OK.sub(" ", cmd)
    if ">" in stripped:
        raise BlockedCommand(f"output redirection to a file is not allowed: {cmd[:100]}")
    s = stripped.replace("$(", ";").replace("`", ";")
    for part in _SPLIT.split(s):
        part = part.strip()
        if not part or not re.match(r"^[\w/.\[!{-]", part):
            continue
        try:
            words = shlex.split(part)
        except ValueError:
            words = part.split()
        reason = _check_words(words)
        if reason:
            raise BlockedCommand(f"{reason}: {part[:100]}")


HOST_ALLOWED = {"shell", "exec-out", "pull", "devices", "version", "features", "get-state", "get-serialno",
                "bugreport", "wait-for-device", "start-server"}

# --------------------------------------------------------------------------- #
# Results and the wrapper
# --------------------------------------------------------------------------- #
@dataclass
class AdbResult:
    id: str
    argv: list
    cmd: str
    label: str
    rc: int
    stdout: str
    stderr: str
    status: str
    partial: bool = False
    started: str = ""
    duration: float = 0.0
    attempts: int = 1
    raw_file: Optional[str] = None
    note: str = ""

    @property
    def ok(self) -> bool:
        return self.status == OK

    @property
    def text(self) -> str:
        return self.stdout.strip("\n")

    def meta(self) -> dict:
        return {"id": self.id, "label": self.label, "cmd": self.cmd, "argv": self.argv, "exit_code": self.rc,
                "status": self.status, "partial": self.partial, "started": self.started,
                "duration_s": round(self.duration, 3), "attempts": self.attempts,
                "stdout_bytes": len(self.stdout.encode("utf-8", "replace")),
                "stderr_bytes": len(self.stderr.encode("utf-8", "replace")),
                "stderr_head": self.stderr.strip()[:200], "raw_file": self.raw_file, "note": self.note}


Runner = Callable[[Sequence[str], float], "tuple[int, bytes, bytes, bool]"]


def subprocess_runner(argv: Sequence[str], timeout: float) -> tuple[int, bytes, bytes, bool]:
    """List-form argv only (no host shell): no quoting issues on Windows/PowerShell."""
    try:
        p = subprocess.run(list(argv), capture_output=True, timeout=timeout, stdin=subprocess.DEVNULL)
        return p.returncode, p.stdout, p.stderr, False
    except subprocess.TimeoutExpired as e:
        return 124, e.stdout or b"", e.stderr or b"", True
    except FileNotFoundError as e:
        return 127, b"", str(e).encode(), False
    except OSError as e:
        return 126, b"", str(e).encode(), False


def decode(b: bytes) -> str:
    return b.decode("utf-8", errors="replace").replace("\r\r\n", "\n").replace("\r\n", "\n")


class Adb:
    def __init__(self, adb_bin: str, serial: Optional[str] = None, timeout: int = 30, retries: int = 1,
                 retry_delay: float = 1.0, runner: Optional[Runner] = None, raw_dir: Optional[Path] = None,
                 echo: Optional[Callable[[str], None]] = None, read_only: bool = True) -> None:
        self.adb_bin, self.serial, self.timeout = adb_bin, serial, timeout
        self.retries, self.retry_delay = retries, retry_delay
        self.runner = runner or subprocess_runner
        self.raw_dir = Path(raw_dir) if raw_dir else None
        self.echo = echo
        self.read_only = read_only
        self.log: list[dict] = []
        self._n = 0

    # -- core ---------------------------------------------------------------
    def _base(self) -> list[str]:
        return [self.adb_bin] + (["-s", self.serial] if self.serial else [])

    def _save_raw(self, res: AdbResult, out: str, err: str) -> None:
        if not self.raw_dir:
            return
        self.raw_dir.mkdir(parents=True, exist_ok=True)
        name = f"{res.id}_{safe_filename(res.label or res.cmd, 48)}.txt"
        (self.raw_dir / name).write_text(out, encoding="utf-8", newline="\n")
        res.raw_file = f"raw/{name}"
        if err.strip():
            (self.raw_dir / f"{res.id}_{safe_filename(res.label or res.cmd, 48)}.stderr.txt").write_text(
                err, encoding="utf-8", newline="\n")

    def run(self, args: Sequence[str], *, timeout: Optional[float] = None, label: str = "",
            retries: Optional[int] = None, ok_codes: Sequence[int] = (0,), save: bool = True) -> AdbResult:
        args = [str(a) for a in args]
        self._n += 1
        rid = f"c{self._n:04d}"
        argv = self._base() + args
        cmd = args[1] if args and args[0] == "shell" and len(args) > 1 else " ".join(args)
        if args and args[0] not in HOST_ALLOWED:
            return self._blocked(rid, argv, cmd, label, f"adb subcommand '{args[0]}' not allowed")
        if args and args[0] in ("shell", "exec-out") and self.read_only:
            try:
                check_read_only(" ".join(args[1:]))
            except BlockedCommand as e:
                return self._blocked(rid, argv, cmd, label, str(e))
        tmo = timeout or self.timeout
        attempts, started = 0, dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
        t0 = time.monotonic()
        while True:
            attempts += 1
            rc, out_b, err_b, timed_out = self.runner(argv, tmo)
            out, err = decode(out_b), decode(err_b)
            if rc in ok_codes:
                rc_eff = 0
            else:
                rc_eff = rc
            status, partial = classify(rc_eff, out, err, timed_out)
            retryable = status == TIMEOUT or (status in (FAILED, UNSUPPORTED) and TRANSPORT_RE.search(err))
            if retryable and attempts <= (self.retries if retries is None else retries):
                if TRANSPORT_RE.search(err):
                    self.runner(self._base() + ["wait-for-device"], 15)
                time.sleep(self.retry_delay)
                continue
            break
        res = AdbResult(rid, argv, cmd, label or cmd[:60], rc, out, err, status, partial, started,
                        time.monotonic() - t0, attempts)
        if save:
            self._save_raw(res, out, err)
        self.log.append(res.meta())
        if self.echo:
            self.echo(f"      {rid} [{status}{'*' if partial else ''}] {cmd[:90]}")
        return res

    def _blocked(self, rid, argv, cmd, label, why) -> AdbResult:
        res = AdbResult(rid, argv, cmd, label or cmd[:60], -1, "", why, BLOCKED, started=dt.datetime.now(
            dt.timezone.utc).isoformat(timespec="seconds"), note="refused by read-only guard")
        self.log.append(res.meta())
        return res

    # -- conveniences ----------------------------------------------------------
    def shell(self, cmd: str, **kw) -> AdbResult:
        return self.run(["shell", cmd], **kw)

    def text(self, cmd: str, **kw) -> str:
        r = self.shell(cmd, **kw)
        return r.text if r.status == OK else ""

    def first_ok(self, cmds: Sequence[str], **kw) -> AdbResult:
        """Fallback chain. Returns the first usable result, else an 'empty' one, else the last attempt."""
        last, empty = None, None
        for c in cmds:
            last = self.shell(c, **kw)
            if last.status == OK:
                return last
            if last.status == EMPTY and empty is None:
                empty = last
        return empty or last  # type: ignore[return-value]

    def batch(self, items: Sequence[str], inner: str, *, chunk: int = 25, label: str = "",
              **kw) -> tuple[dict[str, str], list[AdbResult]]:
        """Run `inner` (which may reference $p) once per item in a single round-trip per chunk.
        Items must already be validated as shell-safe tokens (package names, integers)."""
        out: dict[str, str] = {}
        results: list[AdbResult] = []
        for i in range(0, len(items), chunk):
            part = list(items[i:i + chunk])
            cmd = f'for p in {" ".join(part)}; do echo "{BATCH_MARK} $p"; {inner}; done; true'
            res = self.shell(cmd, label=f"{label}[{i}:{i + len(part)}]", **kw)
            results.append(res)
            cur, buf = None, []
            for line in res.stdout.splitlines():
                if line.startswith(BATCH_MARK + " "):
                    if cur is not None:
                        out[cur] = "\n".join(buf)
                    cur, buf = line[len(BATCH_MARK) + 1:].strip(), []
                else:
                    buf.append(line)
            if cur is not None:
                out[cur] = "\n".join(buf)
        return out, results

    def summary(self) -> dict[str, int]:
        c = {s: 0 for s in STATUSES}
        for m in self.log:
            c[m["status"]] = c.get(m["status"], 0) + 1
        c["total"] = len(self.log)
        return c


# --------------------------------------------------------------------------- #
# Host-side discovery
# --------------------------------------------------------------------------- #
def find_adb(requested: str, script_dir: Optional[Path] = None) -> Optional[str]:
    import shutil
    if requested != "adb":
        return shutil.which(requested) or (requested if Path(requested).is_file() else None)
    names = ("adb.exe", "adb") if os.name == "nt" else ("adb",)
    for folder in (script_dir or Path(__file__).resolve().parent.parent, Path.cwd()):
        for n in names:
            if (folder / n).is_file():
                return str(folder / n)
    return shutil.which("adb")


def list_devices(adb_bin: str, runner: Optional[Runner] = None) -> list[tuple[str, str, str]]:
    rc, out, err, to = (runner or subprocess_runner)([adb_bin, "devices", "-l"], 30)
    if to:
        raise AdbError("`adb devices` timed out - try `adb kill-server` and retry.")
    devs = []
    for line in decode(out).splitlines():
        line = line.strip()
        if not line or line.startswith(("List of", "*")):
            continue
        p = line.split(None, 2)
        if len(p) >= 2:
            devs.append((p[0], p[1], p[2] if len(p) > 2 else ""))
    return devs


def pick_device(adb_bin: str, wanted: Optional[str], runner: Optional[Runner] = None) -> str:
    devs = list_devices(adb_bin, runner)
    if wanted:
        for s, st, _ in devs:
            if s == wanted:
                if st != "device":
                    raise AdbError(f"Device {wanted} is in state '{st}'.")
                return s
        raise AdbError(f"Device {wanted} not found. Seen: {[d[0] for d in devs] or 'none'}")
    ready = [s for s, st, _ in devs if st == "device"]
    if len(ready) == 1:
        return ready[0]
    if len(ready) > 1:
        raise AdbError("Multiple devices connected, pick one with -s: " + ", ".join(ready))
    if devs:
        raise AdbError("No usable device: " + ", ".join(f"{s} ({st})" for s, st, _ in devs) +
                       ". 'unauthorized' = accept the RSA prompt on the phone; 'offline' = replug / toggle USB debugging.")
    raise AdbError("No device found. Enable USB debugging, connect the phone, and check `adb devices`.")
