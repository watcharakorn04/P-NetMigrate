"""Helpers shared by the vendor renderers. Renderers read only the IR, never source text."""

from __future__ import annotations

from typing import Optional

from app.core.ir import AclIR, InterfaceIR, NoteIR, Provenance, RedistributeIR, RenderedLine, SyntaxCategory, Vendor
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

    def advisory(self, text: str, source_line: Optional[int] = None, warning: Optional[str] = None) -> None:
        """System-written advice as a target-vendor comment (never a command, never deployed)."""
        self.lines.append(
            RenderedLine(
                text=f"{self.marker} {text}",
                provenance=Provenance.SYSTEM,
                source_line=source_line,
                is_comment=True,
                warning=warning,
            )
        )

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


WARN_DEFAULT_GATEWAY = (
    "Cisco ใช้ ip default-gateway เมื่อปิด ip routing บนสวิตช์ แต่ Huawei ไม่มีคำสั่งนี้ "
    "จึงเขียนเป็นเส้นทางคงที่ไปยัง 0.0.0.0 0.0.0.0 แทน (Preference ค่าเริ่มต้น 60) "
    "กรุณาตรวจสอบว่าเหมาะกับบทบาทของอุปกรณ์ปลายทาง"
)
WARN_RIP_NO_VERSION = (
    "ต้นทางไม่ได้ระบุ version 2 — ระบบรองรับเฉพาะ RIPv2 และค่าเริ่มต้นของทั้งสองยี่ห้อไม่ใช่ RIPv2 "
    "ระบบไม่เดาค่าให้ กรุณาตรวจสอบ version ของ RIP"
)
WARN_BGP_PEER_ENABLE = (
    "Cisco เปิดใช้งานเพื่อนบ้าน BGP ให้อัตโนมัติ แต่ Huawei ต้องสั่ง peer <ip> enable ใน ipv4-family unicast เอง "
    "ถ้าไม่มี เซสชันจะขึ้นแต่ไม่แลกเปลี่ยนเส้นทางโดยไม่มีอะไรเตือน ระบบจึงเพิ่มให้"
)
WARN_ACL_NUMBER_ASSIGNED = (
    "ระบบกำหนดหมายเลข ACL ใหม่ตามชนิดของ ACL (ไม่ได้คัดลอกหมายเลขเดิม) — "
    "หมายเลขนี้อาจชนกับ ACL ที่มีอยู่แล้วบนอุปกรณ์ปลายทาง กรุณาตรวจสอบก่อนใช้งาน"
)
WARN_HUAWEI_ACL_NAME = "ชื่อ ACL ของ Huawei ต้องขึ้นต้นด้วยตัวอักษรและยาวไม่เกิน 32 ตัวอักษร กรุณาตรวจสอบ"
WARN_STELNET = (
    "Huawei ต้องเปิดบริการ SSH ด้วยคำสั่ง stelnet server enable — ระบบไม่เติมคำสั่งนี้ให้เอง (เขียนไว้เป็นคำแนะนำใน Comment) "
    "และยังต้องสร้าง RSA key (rsa local-key-pair create) และตั้งค่าบัญชีผู้ใช้ SSH เองบนอุปกรณ์ปลายทาง (ระบบไม่แปลงบัญชีผู้ใช้)"
)
ADVISORY_STELNET = "แนะนำให้เปิดใช้งาน SSH Server เพิ่มเติมด้วยคำสั่ง: stelnet server enable"
WARN_CISCO_SSH = (
    "Cisco ต้องมี ip domain name และ RSA key (crypto key generate rsa) ก่อน SSH จะใช้งานได้ "
    "ระบบไม่สร้าง key และไม่แปลงบัญชีผู้ใช้ให้ กรุณาตั้งค่าเองบนอุปกรณ์ปลายทาง"
)
WARN_HUAWEI_VTY_RANGE = "Huawei หลายรุ่นรองรับ VTY 0–4 (บางรุ่นถึง 0–14) กรุณาตรวจสอบช่วง VTY บนอุปกรณ์ปลายทาง"


def cisco_redistribute(r: RedistributeIR, into: str) -> str:
    """`into` = target protocol ("ospf" | "rip" | "bgp")."""
    source = {"ospf": f"ospf {r.process_id}", "rip": "rip"}.get(r.protocol, r.protocol)
    parts = ["redistribute", source]
    if into == "ospf":
        parts.append("subnets")
    parts += ["metric", str(r.metric)]
    if r.metric_type is not None:
        parts += ["metric-type", str(r.metric_type)]
    return " ".join(parts)


def huawei_import_route(r: RedistributeIR, into: str) -> str:
    source = {"connected": "direct", "ospf": f"ospf {r.process_id}", "rip": f"rip {r.process_id}"}.get(r.protocol, r.protocol)
    parts = ["import-route", source, "med" if into == "bgp" else "cost", str(r.metric)]
    if r.metric_type is not None:
        parts += ["type", str(r.metric_type)]
    return " ".join(parts)


def rip_pid_warning(pid: int) -> Optional[str]:
    if pid == 1:
        return None
    return f"Cisco มี RIP ได้ Process เดียวและไม่มีหมายเลข — หมายเลข Process {pid} ของ Huawei จะไม่ถูกใช้"


def acl_default_action_warning(acl: Optional[AclIR], target: Vendor) -> Optional[str]:
    """Unmatched packets: Cisco ACL denies (implicit deny), Huawei traffic-filter forwards them.

    No warning when the ACL already ends with an explicit catch-all entry.
    """
    if acl is not None and acl.entries and acl.entries[-1].is_catch_all:
        return None
    if target is Vendor.HUAWEI_VRP:
        return (
            "Cisco ปฏิเสธแพ็กเก็ตที่ไม่ตรงกฎใดเลย (implicit deny) แต่ traffic-filter ของ Huawei ปล่อยผ่าน — "
            "ถ้าต้องการพฤติกรรมเดิมให้เพิ่ม rule deny ท้าย ACL เอง"
        )
    return (
        "traffic-filter ของ Huawei ปล่อยแพ็กเก็ตที่ไม่ตรงกฎใดเลยผ่าน แต่ Cisco ปฏิเสธ (implicit deny) — "
        "ถ้าต้องการพฤติกรรมเดิมให้เพิ่ม permit ท้าย ACL เอง"
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
