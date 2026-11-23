"""Helpers shared by the vendor renderers. Renderers read only the IR, never source text."""

from __future__ import annotations

from typing import Optional

from app.core.ir import InterfaceIR, NoteIR, Provenance, RenderedLine, SyntaxCategory, Vendor
from app.core.rules import interface_names

D = SyntaxCategory.DIRECT


class LineWriter:
    def __init__(self, target: Vendor):
        self.target = target
        self.marker = target.comment_marker
        self.lines: list[RenderedLine] = []

    def cmd(
        self,
        text: str,
        category: SyntaxCategory,
        source_line: Optional[int] = None,
        warning: Optional[str] = None,
        provenance: Provenance = Provenance.RULE,
    ) -> None:
        self.lines.append(
            RenderedLine(text=text, provenance=provenance, category=category, source_line=source_line, warning=warning)
        )

    def separator(self) -> None:
        if self.lines and self.lines[-1].text == self.marker:
            return
        self.lines.append(RenderedLine(text=self.marker, provenance=Provenance.RULE, category=D, is_comment=True))

    def comment(self, note: NoteIR) -> None:
        """Free-text source comment with the target vendor's marker (comment-prefix rule)."""
        self.lines.append(
            RenderedLine(
                text=f"{self.marker} {note.text}",
                provenance=Provenance.RULE,
                category=D,
                source_line=note.source_line,
                is_comment=True,
            )
        )

    def notes(self, notes: list[NoteIR]) -> None:
        """Unconverted / not-needed source lines -> target comments with label and reason."""
        for note in notes:
            self.lines.append(
                RenderedLine(
                    text=f"{self.marker} [{note.provenance.value}] {note.text} -- {note.reason}",
                    provenance=note.provenance,
                    source_line=note.source_line,
                    is_comment=True,
                    warning=note.reason,
                )
            )


# ----------------------------------------------------------------------------- warnings (Thai, user-facing)

WARN_STATIC_DEFAULT_PREFERENCE = (
    "ต้นทางไม่ได้ระบุค่าลำดับความสำคัญของเส้นทาง — ค่าเริ่มต้น Cisco AD=1 แต่ Huawei Preference=60 "
    "ระบบไม่เดาค่าให้ กรุณาตรวจสอบว่าลำดับการเลือกเส้นทางยังเหมือนเดิม"
)


def interface_warnings(iface: InterfaceIR, name: str) -> Optional[str]:
    """Warnings attached to the interface header line (slot number, serial default protocol)."""
    warnings: list[str] = []
    slot = interface_names.slot_of(iface.number)
    if not iface.is_virtual and slot:
        warnings.append(
            f"{name}: หมายเลขสล็อต {slot} ไม่ใช่ 0 — ระบบไม่แปลงหมายเลขพอร์ต "
            "กรุณาตรวจสอบว่าพอร์ตนี้มีอยู่จริงบนอุปกรณ์ปลายทาง"
        )
    if iface.if_type == "serial" and iface.link_protocol is None:
        warnings.append(
            f"{name}: ต้นทางไม่ได้ระบุโปรโตคอลของพอร์ต Serial — ค่าเริ่มต้น Cisco คือ HDLC แต่ Huawei คือ PPP "
            "ระบบไม่เดาค่าให้ ถ้าเชื่อมข้ามยี่ห้อต้องตั้งเป็น PPP ทั้งสองฝั่ง"
        )
    return " | ".join(warnings) or None


def hdlc_warning(name: str) -> str:
    return (
        f"{name}: HDLC ของ Cisco กับ HDLC ของ Huawei ทำงานร่วมกันไม่ได้ "
        "ถ้าเชื่อมข้ามยี่ห้อต้องเปลี่ยนเป็น PPP ทั้งสองฝั่ง"
    )


def trunk_warning(iface: InterfaceIR, name: str) -> Optional[str]:
    if iface.port_mode != "trunk" or iface.trunk_allowed_vlans is not None:
        return None
    return (
        f"{name}: พอร์ต trunk ไม่ได้ระบุรายการ VLAN — Cisco อนุญาตทุก VLAN แต่ Huawei อนุญาตเฉพาะ VLAN 1 "
        "ระบบไม่เดาค่าให้ กรุณาระบุรายการ VLAN เอง"
    )
