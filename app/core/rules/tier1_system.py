"""Tier 1 — System-level rules (proposal §2.3.1 item 1.3.1).

  hostname <name>                         <-> sysname <name>          (D)
  ip domain-name <d> / ip domain name <d> <-> dns domain <d>          (D)
  end                                     <-> return                  (D, file assembly)
  "!" comment                             <-> "#" comment             (D, comment prefix)
"""

from __future__ import annotations

import re
from typing import Optional

from app.core.ir import SyntaxCategory, Vendor
from app.core.rules.base import REASON_NO_RULE, Block, BlockHandler, ParseContext

D = SyntaxCategory.DIRECT

_CISCO_COMMENT = re.compile(r"^!+\s*(.*)$")
_HUAWEI_COMMENT = re.compile(r"^[#!]+\s*(.*)$")  # VRP output also uses "!Software Version ..."


def comment_body(body: str, vendor: Vendor) -> Optional[str]:
    """Text of a comment line ("" for a bare separator); None if the line is not a comment."""
    m = (_CISCO_COMMENT if vendor is Vendor.CISCO_IOS_XE else _HUAWEI_COMMENT).match(body)
    return m[1].strip() if m else None


def _system_handler(hostname_re: str, domain_re: str, end_re: str) -> BlockHandler:
    hostname_p = re.compile(hostname_re, re.IGNORECASE)
    domain_p = re.compile(domain_re, re.IGNORECASE)
    end_p = re.compile(end_re, re.IGNORECASE)

    def handler(block: Block, ctx: ParseContext) -> bool:
        line = block.header
        if m := hostname_p.match(line.body):
            ctx.ir.hostname = m[1]
            ctx.ir.field_lines["hostname"] = line.no
        elif m := domain_p.match(line.body):
            ctx.ir.domain_name = m[1]
            ctx.ir.field_lines["domain_name"] = line.no
        elif not end_p.match(line.body):
            return False
        ctx.rule(line, D)
        ctx.unconverted_children(block, REASON_NO_RULE, ctx.ir.notes)
        return True

    return handler


cisco_system = _system_handler(r"^hostname\s+(\S+)$", r"^ip\s+domain[-\s]name\s+(\S+)$", r"^end$")
cisco_system.__name__ = "cisco_system"
huawei_system = _system_handler(r"^sysname\s+(\S+)$", r"^dns\s+domain\s+(\S+)$", r"^return$")
huawei_system.__name__ = "huawei_system"

CISCO_HANDLERS: list[BlockHandler] = [cisco_system]
HUAWEI_HANDLERS: list[BlockHandler] = [huawei_system]
