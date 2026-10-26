"""Shared context, profiles, findings model and Markdown helpers."""
from __future__ import annotations

import argparse
import re
from dataclasses import dataclass, field, asdict
from typing import Any, Callable, Optional

from .adb import Adb, AdbResult, EMPTY, OK, STATUSES

LEVELS = {"quick": 0, "deep": 1, "exhaustive": 2}
SEVERITIES = ("critical", "high", "medium", "low", "info")
CONFIDENCES = ("high", "medium", "low")


# ------------------------------------------------------------------ markdown helpers
def esc(v: object) -> str:
    return str(v).replace("|", "\\|").replace("\n", " ").strip()


def fence(text: str, lang: str = "") -> str:
    f = "````" if "```" in text else "```"
    return f"{f}{lang}\n{text.rstrip()}\n{f}"


def table(headers: list[str], rows: list[list[object]]) -> str:
    if not rows:
        return "_none_"
    out = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    out += ["| " + " | ".join(esc(c) for c in r) + " |" for r in rows]
    return "\n".join(out)


def details(summary: str, body: str) -> str:
    return f"<details>\n<summary>{summary}</summary>\n\n{body}\n\n</details>"


def or_na(v: object) -> str:
    s = "" if v is None else str(v).strip()
    return s if s and s != "null" else "n/a"


def fmt_kb(kb: float) -> str:
    return f"{kb / 1024:.0f} MB" if kb < 1024 * 1024 else f"{kb / 1024 / 1024:.1f} GB"


def fmt_bytes(b: float) -> str:
    if b < 1024:
        return f"{int(b)} B"
    return fmt_kb(b / 1024) if b >= 1024 * 1024 else f"{b / 1024:.0f} KB"


def clip(text: str, n: int = 40) -> str:
    lines = text.splitlines()
    return "\n".join(lines[:n]) + (f"\n... ({len(lines) - n} more lines in raw file)" if len(lines) > n else "")


# ------------------------------------------------------------------ findings
@dataclass
class Finding:
    id: str
    title: str
    severity: str            # critical|high|medium|low|info
    confidence: str          # high|medium|low
    category: str
    observations: list = field(default_factory=list)   # directly observed facts
    heuristics: list = field(default_factory=list)     # interpretation / inference (never presented as fact)
    evidence: list = field(default_factory=list)       # command ids / data keys
    recommendation: str = ""

    @property
    def kind(self) -> str:
        return "heuristic" if self.heuristics else "observed"


# ------------------------------------------------------------------ specs
@dataclass
class Spec:
    """A table-driven read-only query with a fallback chain of device commands."""
    key: str
    title: str
    cmds: list
    level: int = 0
    timeout: Optional[int] = None
    parser: Optional[Callable[[str], Any]] = None
    show: int = 30            # lines shown in the Markdown report (0 = hide, raw file still kept)
    needs: tuple = ()         # tool names that must exist; else recorded as unsupported without running


@dataclass
class Item:
    key: str
    title: str
    status: str
    cmd_id: Optional[str]
    text: str = ""
    parsed: Any = None


class Ctx:
    def __init__(self, adb: Adb, args: argparse.Namespace, props: dict[str, str]) -> None:
        self.adb, self.args, self.props = adb, args, props
        self.level = LEVELS[args.profile]
        self.sections: list[tuple[str, str]] = []
        self.findings: list[Finding] = []
        self.data: dict[str, Any] = {}
        self.items: dict[str, Item] = {}
        self.caps: dict[str, Any] = {"tools": {}, "services": [], "cmd_services": [], "adb_features": []}
        self.settings: dict[str, str] = {}
        self.users: list[dict] = []
        self.current_user = 0
        self.target_users: list[int] = [0]
        self.packages: dict[str, dict] = {}       # canonical per-package records
        self.third: set[str] = set()
        self.disabled: set[str] = set()
        self.uid_map: dict[int, list[str]] = {}
        self.procs: list[dict] = []
        self.sockets: list[dict] = []
        self.warnings: list[str] = []
        self.module_status: dict[str, str] = {}
        self.progress: Callable[[str], None] = lambda m: None
        self.artifacts: list[str] = []
        self.out_dir = None
        self._fid = 0

    # -- helpers
    @property
    def sdk(self) -> int:
        try:
            return int(self.props.get("ro.build.version.sdk", "0"))
        except ValueError:
            return 0

    def has_tool(self, *names: str) -> bool:
        t = self.caps["tools"]
        return all(t.get(n, True) for n in names)  # unknown tools are assumed present

    def setting(self, ns: str, key: str) -> str:
        return or_na(self.settings.get(f"{ns}/{key}"))

    def add(self, title: str, body: str) -> None:
        self.sections.append((title, body))

    def find(self, title: str, severity: str, confidence: str, category: str, observations=(), heuristics=(),
             evidence=(), recommendation: str = "") -> Finding:
        self._fid += 1
        f = Finding(f"F{self._fid:03d}", title, severity, confidence, category, list(observations),
                    list(heuristics), list(evidence), recommendation)
        self.findings.append(f)
        return f

    def user_args(self, user: Optional[int] = None) -> str:
        return f"--user {self.current_user if user is None else user}"

    # -- running specs
    def run_spec(self, s: Spec) -> Item:
        if s.level > self.level:
            it = Item(s.key, s.title, "skipped-by-profile", None)
        elif s.needs and not self.has_tool(*s.needs):
            it = Item(s.key, s.title, "unsupported", None)
            self.adb.log.append({"id": f"s-{s.key}", "label": s.key, "cmd": s.cmds[0], "argv": [], "exit_code": None,
                                 "status": "unsupported", "partial": False, "started": "", "duration_s": 0, "attempts": 0,
                                 "stdout_bytes": 0, "stderr_bytes": 0, "stderr_head": "", "raw_file": None,
                                 "note": f"skipped: tool(s) {s.needs} not present on device"})
        else:
            r = self.adb.first_ok(s.cmds, timeout=s.timeout, label=s.key)
            parsed = None
            if r.status == OK and s.parser:
                try:
                    parsed = s.parser(r.text)
                except Exception as e:  # parser diagnostics, never fatal
                    self.diag(s.key, f"parser error {type(e).__name__}: {e}")
            it = Item(s.key, s.title, r.status, r.id, r.text if r.status == OK else "", parsed)
        self.items[s.key] = it
        return it

    def run_specs(self, specs: list[Spec]) -> list[Item]:
        return [self.run_spec(s) for s in specs]

    def diag(self, where: str, msg: str) -> None:
        self.data.setdefault("parser_diagnostics", []).append({"where": where, "message": msg})

    def render_items(self, items: list[Item], specs: list[Spec]) -> str:
        by = {s.key: s for s in specs}
        rows = [[i.title, i.status, i.cmd_id or "-", len(i.text.splitlines()) if i.text else 0] for i in items
                if i.status != "skipped-by-profile"]
        body = table(["Query", "Status", "Cmd", "Lines"], rows)
        for i in items:
            if i.status == OK and by[i.key].show:
                body += "\n\n" + details(f"{i.title} (`{i.cmd_id}`)", fence(clip(i.text, by[i.key].show)))
        return body

    def evidence(self, *keys: str) -> list[str]:
        return [self.items[k].cmd_id for k in keys if k in self.items and self.items[k].cmd_id]

    def fetch(self, key: str) -> str:
        it = self.items.get(key)
        return it.text if it and it.status == OK else ""
