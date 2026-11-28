"""Deterministic credential filter — the security gate.

Security Non-Negotiables #1 and #2 (see CLAUDE.md §4):
  * Runs BEFORE any request to an external AI service is assembled, in every mode.
  * Stripped values never reach output files, not even inside comments; a fixed-text
    advisory is emitted instead telling the admin to reconfigure manually.

Design choices:
  * Pure regex rules, no AI. Same input -> same output.
  * Both vendors' rule sets are ALWAYS applied, whatever vendor was declared, so a
    mis-labelled upload cannot leak secrets.
  * Whole lines are removed (not redacted in place): usernames are sensitive too, and
    a half-redacted line is not a valid command anyway.
  * Advisory text is built only from fixed strings + the line number; it never
    interpolates any part of the original line.
  * Bias toward false positives: a stripped harmless line costs one advisory, a missed
    secret is a breach.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from app.core.ir import Provenance, Vendor

# (compiled pattern, category shown in the advisory). Patterns run against the line with
# leading whitespace and any leading comment marker removed. Order = first match wins.
_RULES: list[tuple[re.Pattern[str], str]] = [
    # ---- Cisco IOS-XE
    (r"^username\s", "บัญชีผู้ใช้ (username)"),
    (r"^enable\s+(secret|password)\b", "รหัสผ่าน enable"),
    (r"^snmp-server\s+(community|user|host)\b", "SNMP community/user"),
    (r"^(tacacs|radius)(-server)?\b.*\bkey\b", "คีย์ TACACS+/RADIUS"),
    (r"^neighbor\s+\S+\s+password\b", "รหัสผ่าน BGP neighbor"),
    (r"^ip\s+ospf\s+(message-digest-key|authentication-key)\b", "คีย์ยืนยันตัวตน OSPF"),
    (r"^ntp\s+authentication-key\b", "คีย์ยืนยันตัวตน NTP"),
    (r"^crypto\s+(key|isakmp\s+key|pki)\b", "คีย์เข้ารหัส (crypto key)"),
    (r"^key-string\b", "key-string"),
    (r"^key\s+\d*\s*\S+", "คีย์ (key)"),
    # ---- Huawei VRP
    (r"^local-user\s", "บัญชีผู้ใช้ (local-user)"),
    (r"^super\s+password\b", "รหัสผ่าน super"),
    (r"^set\s+authentication\s+password\b", "รหัสผ่าน VTY/Console"),
    (r"^snmp-agent\s+(community|usm-user|target-host)\b", "SNMP community/user"),
    (r"^peer\s+\S+\s+password\b", "รหัสผ่าน BGP peer"),
    (r"^(ospf\s+|area-)?authentication-mode\s+(md5|hmac-sha256|simple|keychain)\b", "คีย์ยืนยันตัวตน OSPF"),
    (r"^rip\s+authentication-mode\s+(md5|hmac-sha256|simple)\b", "คีย์ยืนยันตัวตน RIP"),
    (r"^(hwtacacs|radius)-server\b.*\bshared-key\b", "คีย์ HWTACACS/RADIUS"),
    (r"^ssh\s+user\s", "บัญชีผู้ใช้ SSH"),
    # ---- Generic catch-all (any vendor, any position, including comments)
    (r"\b(password|passwd|secret|cipher|irreversible-cipher|shared-key|community)\b", "ข้อมูลลับ"),
]
_COMPILED = [(re.compile(p, re.IGNORECASE), cat) for p, cat in _RULES]

# Lines that contain a trigger word but hold no secret value.
_ALLOW = [
    re.compile(p, re.IGNORECASE)
    for p in (
        r"^(no\s+)?service\s+password-(encryption|recovery)\s*$",
        r"^authentication-mode\s+(aaa|password|none)\s*$",
    )
]

_LEADING_COMMENT = re.compile(r"^[!#]+\s*")


@dataclass
class SanitizedResult:
    """Output of the security gate.

    sanitized_text         — input minus every credential line; the ONLY text allowed to be
                             sent to an external AI service.
    stripped_line_numbers  — 1-based source line numbers that were removed.
    advisory_lines         — one comment per stripped line, in the advisory vendor's comment
                             syntax, containing zero secret material.
    """

    sanitized_text: str
    stripped_line_numbers: list[int] = field(default_factory=list)
    advisory_lines: list[str] = field(default_factory=list)


def _classify(line: str) -> Optional[str]:
    body = _LEADING_COMMENT.sub("", line.strip())
    if not body:
        return None
    if any(a.match(body) for a in _ALLOW):
        return None
    for pattern, category in _COMPILED:
        if pattern.search(body):
            return category
    return None


def contains_secret(line: str) -> bool:
    """True if this single line holds a credential / username / key."""
    return _classify(line) is not None


# Interactive commands: they prompt ([Y/N], key modulus size, ...) and hang a scripted CLI
# push. Key generation is also secret material the admin must create on the device. They are
# never emitted, never deployed; an AI answer containing one is replaced by an advisory.
_INTERACTIVE = [
    re.compile(p, re.IGNORECASE)
    for p in (
        r"^(rsa|dsa|ecc|sm2)\s+local-key-pair\s+create\b",  # Huawei VRP key generation
        r"^crypto\s+key\s+generate\b",  # Cisco IOS-XE key generation
    )
]


def is_interactive_command(line: str) -> bool:
    """True for commands that prompt interactively (e.g. `rsa local-key-pair create`)."""
    body = line.strip()
    return bool(body) and not body.startswith(("!", "#")) and any(p.match(body) for p in _INTERACTIVE)


def _advisory(marker: str, line_no: int, category: str) -> str:
    return (
        f"{marker} [{Provenance.SYSTEM.value}] บรรทัด {line_no}: ตัดข้อมูลลับออก ({category}) "
        f"— ระบบไม่แปลงรหัสผ่าน/บัญชีผู้ใช้ กรุณาตั้งค่าใหม่ด้วยตนเองบนอุปกรณ์ปลายทาง"
    )


def strip_secrets(
    text: str,
    vendor: Vendor,
    advisory_vendor: Optional[Vendor] = None,
) -> SanitizedResult:
    """Remove every credential line from `text`.

    vendor           — declared source vendor (informational; all rules run regardless).
    advisory_vendor  — vendor whose comment marker is used for advisories; pass the TARGET
                       vendor when the advisories go into a converted file. Defaults to `vendor`.
    """
    marker = (advisory_vendor or vendor).comment_marker
    kept: list[str] = []
    stripped: list[int] = []
    advisories: list[str] = []

    for idx, raw in enumerate(text.splitlines(keepends=True), start=1):
        category = _classify(raw)
        if category is None:
            kept.append(raw)
        else:
            stripped.append(idx)
            advisories.append(_advisory(marker, idx, category))

    return SanitizedResult(
        sanitized_text="".join(kept),
        stripped_line_numbers=stripped,
        advisory_lines=advisories,
    )


def strip_secrets_keep_lines(text: str, vendor: Vendor) -> str:
    """Like `strip_secrets`, but each stripped line is REPLACED by its fixed-text advisory
    (in `vendor`'s comment syntax) instead of removed, so line N of the result is still
    line N of the source. Used for text that is persisted (audit history before/after view).
    """
    sanitized = strip_secrets(text, vendor)
    advisory = dict(zip(sanitized.stripped_line_numbers, sanitized.advisory_lines))
    out = [advisory.get(no, line) for no, line in enumerate(text.splitlines(), start=1)]
    return "\n".join(out) + ("\n" if out else "")
