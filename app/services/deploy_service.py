"""Configuration deployment (proposal §2.3.1 module 4, Security Non-Negotiable #3).

Pipeline:  labelled lines / text ─► build_plan()  (strip_secrets + filter)  ─► user reviews and
           may edit (4.1) ─► confirm (4.4) ─► final re-filter ─► simulation (default) | live Netmiko

Before ANY push (4.5) these are removed, in every mode, on every path:
  * comment lines (`!` / `#`), including every "แปลงไม่ได้" / "ไม่ต้องใช้คำสั่งนี้" comment;
  * lines labelled "มาจาก AI ต้องตรวจสอบก่อนใช้" or "แปลงไม่ได้" — the label follows the text, so an
    AI line pasted back verbatim into the edited command list is still removed;
  * credential / user-account lines (`strip_secrets` + `contains_secret`);
  * interactive commands that would hang the push (`rsa local-key-pair create`, ...).
If AI-labelled lines were present, deployment is blocked until the user explicitly ticks the
review acknowledgement (they were removed and must be reviewed/configured by hand).

Live mode connects ONLY to self-built EVE-NG virtual devices (§2.3.2 item 1): the device must
be in the inventory and the user must confirm it is an EVE-NG lab node. SSH credentials are
passed straight to the worker thread, never logged, never written to SQLite, and dropped as
soon as the connection is made.
"""

from __future__ import annotations

import json
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Optional

from app.core.ir import Provenance, Vendor
from app.core.secret_stripper import contains_secret, is_interactive_command, strip_secrets
from app.db import Database, utcnow

try:  # optional at import time so the app still serves without the SSH stack
    from netmiko import ConnectHandler  # type: ignore
except Exception:  # pragma: no cover
    ConnectHandler = None  # type: ignore

NETMIKO_DEVICE_TYPE = {Vendor.CISCO_IOS_XE: "cisco_xe", Vendor.HUAWEI_VRP: "huawei"}
LEVELS = ("INFO", "SUCCESS", "WARNING", "ERROR", "COMMAND")
SIM_DELAY = 0.15  # seconds between simulated log lines (so the SSE stream is visibly live)
# Mode entry/exit and save lines are never pushed: Netmiko enters and leaves config mode
# itself and saves with save_config() after a successful push.
TERMINATORS = {
    "end", "return",
    "configure terminal", "conf t", "system-view",
    "save", "save force", "write", "write memory", "wr", "copy running-config startup-config",
}

# Removal reasons (stable codes; the UI translates them)
R_COMMENT = "comment"
R_AI = "ai_review"
R_UNCONVERTED = "unconverted"
R_SECRET = "credential"
R_TERMINATOR = "terminator"
R_NOT_NEEDED = "not_needed"
R_INTERACTIVE = "interactive"
_BLOCKED_LABELS = {Provenance.AI.name, Provenance.UNCONVERTED.name}


class DeployError(Exception):
    """A guardrail refused the request (message is safe to show)."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


@dataclass
class DeployPlan:
    vendor: Vendor
    commands: list[str]
    removed: list[dict]  # {"line": int, "text": str, "reason": str} — text omitted for credentials
    ai_review_count: int
    unconverted_count: int
    blocked_texts: list[str] = field(default_factory=list)  # AI/unconverted texts (for re-filtering edits)

    @property
    def requires_review_ack(self) -> bool:
        return self.ai_review_count > 0

    def to_json(self) -> dict:
        return {
            "vendor": self.vendor.value,
            "commands": self.commands,
            "removed": self.removed,
            "ai_review_count": self.ai_review_count,
            "unconverted_count": self.unconverted_count,
            "requires_review_ack": self.requires_review_ack,
        }


def _is_comment(text: str, vendor: Vendor) -> bool:
    s = text.strip()
    return s.startswith("!") or s.startswith("#")


def build_plan(lines: Iterable[dict], vendor: Vendor) -> DeployPlan:
    """Filter labelled lines ({text, provenance(enum name), is_comment?}) into a deployable plan."""
    lines = list(lines)
    raw = "\n".join(l.get("text", "") for l in lines)
    stripped = set(strip_secrets(raw, vendor).stripped_line_numbers)  # Non-Negotiable #3
    commands: list[str] = []
    removed: list[dict] = []
    blocked: list[str] = []
    ai = unconverted = 0
    for no, line in enumerate(lines, start=1):
        text = (line.get("text") or "").rstrip()
        prov = line.get("provenance") or Provenance.RULE.name
        if not text.strip():
            continue
        if no in stripped or contains_secret(text):
            removed.append({"line": no, "text": "", "reason": R_SECRET})  # never echo the credential
            continue
        if is_interactive_command(text):
            removed.append({"line": no, "text": text, "reason": R_INTERACTIVE})
            continue
        if prov == Provenance.AI.name:
            if not (line.get("is_comment") or _is_comment(text, vendor)):
                ai += 1
                blocked.append(text.strip())
            removed.append({"line": no, "text": text, "reason": R_AI})
            continue
        if prov == Provenance.UNCONVERTED.name:
            unconverted += 1
            blocked.append(text.strip())
            removed.append({"line": no, "text": text, "reason": R_UNCONVERTED})
            continue
        if line.get("is_comment") or _is_comment(text, vendor):
            removed.append({"line": no, "text": text, "reason": R_COMMENT})
            continue
        # Strict allow-list: only labels that are deployable (RULE / SYSTEM) are ever pushed.
        label = Provenance.__members__.get(prov)
        if label is None or not label.deployable:
            removed.append({"line": no, "text": text, "reason": R_NOT_NEEDED})
            continue
        if text.strip().lower() in TERMINATORS:
            removed.append({"line": no, "text": text, "reason": R_TERMINATOR})
            continue
        commands.append(text)
    return DeployPlan(vendor, commands, removed, ai, unconverted, blocked)


def plan_from_text(text: str, vendor: Vendor) -> DeployPlan:
    """Pasted text has no provenance: comments, terminators and credentials are still removed."""
    return build_plan(({"text": t, "provenance": Provenance.RULE.name} for t in text.splitlines()), vendor)


def final_commands(edited: str, vendor: Vendor, blocked_texts: Iterable[str] = ()) -> tuple[list[str], list[dict]]:
    """Re-filter the (possibly user-edited, 4.1) command list right before sending."""
    plan = plan_from_text(edited, vendor)
    blocked = {b.strip() for b in blocked_texts if b.strip()}
    commands, removed = [], list(plan.removed)
    for c in plan.commands:
        if c.strip() in blocked:
            removed.append({"line": None, "text": c, "reason": R_AI})
        else:
            commands.append(c)
    return commands, removed


# ----------------------------------------------------------------------------- jobs & logs


@dataclass
class DeployJob:
    id: str
    deployment_id: int
    mode: str
    logs: list[dict] = field(default_factory=list)
    done: bool = False
    status: str = "running"
    lock: threading.Lock = field(default_factory=threading.Lock)

    def log(self, level: str, message: str) -> None:
        assert level in LEVELS
        with self.lock:
            self.logs.append({"seq": len(self.logs), "ts": utcnow(), "level": level, "message": message})

    def since(self, seq: int) -> list[dict]:
        with self.lock:
            return self.logs[seq:]


_JOBS: dict[str, DeployJob] = {}
_JOBS_LOCK = threading.Lock()


def get_job(job_id: str) -> Optional[DeployJob]:
    with _JOBS_LOCK:
        return _JOBS.get(job_id)


def _finish(db: Database, job: DeployJob, status: str) -> None:
    job.status = status
    with db.connect() as conn:
        conn.execute("UPDATE deployments SET status = ?, finished_at = ?, log_json = ? WHERE id = ?",
                     (status, utcnow(), json.dumps(job.since(0), ensure_ascii=False), job.deployment_id))
    job.done = True


def _simulate(db: Database, job: DeployJob, host: str, commands: list[str], delay: float) -> None:
    try:
        job.log("INFO", f"[SIMULATION] no device is contacted — replaying the push to {host or 'virtual device'}")
        time.sleep(delay)
        job.log("SUCCESS", "[SIMULATION] session opened")
        job.log("INFO", "entering configuration mode")
        for c in commands:
            time.sleep(delay)
            job.log("COMMAND", c)
        job.log("INFO", "leaving configuration mode")
        job.log("SUCCESS", f"[SIMULATION] {len(commands)} command(s) applied")
        _finish(db, job, "success")
    except Exception as exc:  # pragma: no cover
        job.log("ERROR", f"simulation failed: {type(exc).__name__}")
        _finish(db, job, "failed")


def _live(db: Database, job: DeployJob, params: dict[str, Any], commands: list[str]) -> None:
    host = params.get("host", "")
    try:
        if ConnectHandler is None:
            raise RuntimeError("netmiko is not installed")
        job.log("INFO", f"connecting to {host}:{params.get('port')} via SSH ({params['device_type']})")
        conn = ConnectHandler(**params)
        params.clear()  # drop the credentials as soon as the session exists
        try:
            job.log("SUCCESS", "SSH session established")
            for c in commands:
                job.log("COMMAND", c)
            output = conn.send_config_set(commands)
            for line in str(output or "").splitlines():
                if contains_secret(line):
                    continue
                low = line.lower()
                if "% invalid" in low or "error:" in low or "unrecognized command" in low:
                    job.log("WARNING", line.strip())
            try:
                conn.save_config()
                job.log("INFO", "configuration saved")
            except Exception:
                job.log("WARNING", "could not save the configuration automatically — save it on the device")
        finally:
            conn.disconnect()
        job.log("SUCCESS", f"{len(commands)} command(s) sent to {host}")
        _finish(db, job, "success")
    except Exception as exc:
        params.clear()
        # Only the exception TYPE is logged: messages of auth errors may echo the username.
        job.log("ERROR", f"deployment failed: {type(exc).__name__}")
        _finish(db, job, "failed")


def start_deployment(
    db: Database,
    *,
    vendor: Vendor,
    commands: list[str],
    removed: list[dict],
    mode: str = "simulation",
    device: Optional[dict] = None,
    conversion_id: Optional[int] = None,
    username: str = "",
    password: str = "",
    sim_delay: Optional[float] = None,
    runner: Callable[[Callable[[], None]], None] | None = None,
) -> DeployJob:
    """Record the deployment and start it in a worker thread. Returns the job (for SSE)."""
    if mode not in ("simulation", "live"):
        raise DeployError("bad_mode", "mode must be simulation or live")
    if not commands:
        raise DeployError("empty", "no deployable commands remain after filtering")
    if mode == "live" and device is None:
        raise DeployError("no_device", "live mode needs a device from the inventory")
    host = device["ip"] if device else ""
    with db.connect() as conn:
        cur = conn.execute(
            """INSERT INTO deployments (created_at, device_id, device_name, host, vendor, mode, status,
                   conversion_id, commands_json, removed_json) VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (utcnow(), device["id"] if device else None, device["name"] if device else "", host, vendor.value, mode,
             "running", conversion_id, json.dumps(commands, ensure_ascii=False),
             json.dumps(removed, ensure_ascii=False)),
        )
        dep_id = int(cur.lastrowid)
    job = DeployJob(id=uuid.uuid4().hex, deployment_id=dep_id, mode=mode)
    with _JOBS_LOCK:
        _JOBS[job.id] = job
    skipped = len(removed)
    if skipped:
        job.log("WARNING", f"{skipped} line(s) removed before sending (comments / review-required / unconverted / credentials)")

    if mode == "simulation":
        delay = SIM_DELAY if sim_delay is None else sim_delay
        target: Callable[[], None] = lambda: _simulate(db, job, host, commands, delay)
    else:
        params = {
            "device_type": NETMIKO_DEVICE_TYPE[vendor],
            "host": host,
            "port": int(device.get("ssh_port") or 22),  # type: ignore[union-attr]
            "username": username,
            "password": password,
            "fast_cli": False,
        }
        target = lambda: _live(db, job, params, commands)
    (runner or (lambda fn: threading.Thread(target=fn, daemon=True).start()))(target)
    return job


def list_deployments(db: Database, limit: int = 50) -> list[dict]:
    with db.connect() as conn:
        rows = conn.execute(
            "SELECT id, created_at, finished_at, device_id, device_name, host, vendor, mode, status, conversion_id, "
            "commands_json FROM deployments ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["command_count"] = len(json.loads(d.pop("commands_json")))
        out.append(d)
    return out


def get_deployment(db: Database, deployment_id: int) -> Optional[dict]:
    with db.connect() as conn:
        r = conn.execute("SELECT * FROM deployments WHERE id = ?", (deployment_id,)).fetchone()
    if r is None:
        return None
    d = dict(r)
    for k in ("commands", "removed", "log"):
        d[k] = json.loads(d.pop(f"{k}_json"))
    return d


def log_text(deployment: dict) -> str:
    head = [f"NetMigrate deployment #{deployment['id']} — {deployment['mode']} — {deployment['status']}",
            f"device: {deployment['device_name'] or '-'} {deployment['host']}", ""]
    return "\n".join(head + [f"{e['ts']} [{e['level']}] {e['message']}" for e in deployment["log"]]) + "\n"
