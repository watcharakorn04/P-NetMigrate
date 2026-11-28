"""Helpers shared by the vendor renderers. Renderers read only the IR, never source text."""

from __future__ import annotations

from typing import Optional

from app.core.ir import AclIR, BannerIR, InterfaceIR, InterfaceRef, NoteIR, Provenance, RedistributeIR, RenderedLine, SyntaxCategory, Vendor
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

    def note_line(self, note: NoteIR) -> RenderedLine:
        """Unconverted / not-needed source line -> target comment with label and reason."""
        return RenderedLine(
            text=f"{self.marker} [{note.provenance.value}] {note.text} -- {note.reason}",
            provenance=note.provenance,
            source_line=note.source_line,
            is_comment=True,
            warning=note.reason,
        )

    def notes(self, notes: list[NoteIR]) -> None:
        for note in notes:
            self.lines.append(self.note_line(note))

    def exit_view(self, source_line: Optional[int], levels: int = 1) -> None:
        """Explicit view exit written by the source (Cisco `exit` <-> Huawei `quit`).

        `levels` > 1 when the target block nests views (Huawei `ospf` > `area`, `bgp` >
        `ipv4-family`): one exit per level so the next block starts in the right view.
        """
        word = "exit" if self.target is Vendor.CISCO_IOS_XE else "quit"
        for depth in range(levels - 1, -1, -1):
            self.cmd(" " * depth + word, D, source_line)

    def top_level_notes(self, notes: list[NoteIR]) -> None:
        """Place each top-level note (an unconverted/not-needed source block) next to the
        rendered section that precedes it in the SOURCE, instead of piling all of them up at
        the end of the file. The renderer's section order (ACL before interfaces, ...) is
        kept; notes go right after the last section that starts before them. Hybrid mode
        replaces these comments with AI lines in place, so AI output also lands in source order.
        """
        if not notes:
            return
        sections: list[list[RenderedLine]] = [[]]
        for line in self.lines:
            sections[-1].append(line)
            if line.is_comment and line.text == self.marker:
                sections.append([])
        if not sections[-1]:
            sections.pop()

        def start(section: list[RenderedLine]) -> Optional[int]:
            nos = [l.source_line for l in section if not l.is_comment and l.source_line]
            return min(nos) if nos else None

        starts = [start(s) for s in sections]
        after: dict[int, list[NoteIR]] = {}
        for note in sorted(notes, key=lambda n: n.source_line):
            idx = 0  # default: right after the leading comment section
            for i, s in enumerate(starts):
                if s is not None and s < note.source_line:
                    idx = i
            after.setdefault(idx, []).append(note)

        out: list[RenderedLine] = []
        for i, section in enumerate(sections):
            out.extend(section)
            if i in after:
                if out and not (out[-1].is_comment and out[-1].text == self.marker):
                    out.append(RenderedLine(text=self.marker, provenance=Provenance.RULE, category=D, is_comment=True))
                out.extend(self.note_line(n) for n in after[i])
                out.append(RenderedLine(text=self.marker, provenance=Provenance.RULE, category=D, is_comment=True))
        self.lines = out


def interface_header(iface: InterfaceIR, target: Vendor) -> str:
    """`interface <name>`, or the port-range form when the IR holds a range.

    Port numbers are written verbatim (proposal §2.3.2 item 4): only the type name changes.
    """
    name = interface_names.display_name(iface.ref, target)
    if not iface.range_end:
        return f"interface {name}"
    if target is Vendor.CISCO_IOS_XE:
        last = interface_names.split_last(iface.range_end)
        return f"interface range {name} - {last[1] if last else iface.range_end}"
    end = interface_names.display_name(InterfaceRef(if_type=iface.if_type, number=iface.range_end), target)
    return f"port-group group-member {name} to {end}"


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
WARN_HUAWEI_VTY_CLAMPED = (
    "สวิตช์ Huawei ทั่วไปรองรับ VTY 0–4 (ขยายได้ด้วย user-interface maximum-vty บางรุ่น) "
    "ระบบจึงแปลงช่วง VTY ของต้นทางเป็น user-interface vty 0 4 — ถ้าต้องการจำนวน VTY มากกว่านี้ให้ตั้งค่าเองบนอุปกรณ์ปลายทาง"
)
ADVISORY_TRUNK_ALLOW_ALL = (
    "แนะนำ: Cisco อนุญาตทุก VLAN บนพอร์ต trunk เป็นค่าเริ่มต้น แต่ Huawei อนุญาตเฉพาะ VLAN 1 "
    "ถ้าต้องการพฤติกรรมเดิมให้เพิ่มคำสั่ง: port trunk allow-pass vlan all"
)
WARN_SAVE_FORCE = (
    "save force บันทึก Config ทันทีโดยไม่ถามยืนยัน (Y/N) จึงวางคำสั่งแบบไม่โต้ตอบได้ "
    "แต่จะเขียนทับ Config ที่บันทึกไว้เดิมบนอุปกรณ์ — การ Deploy ผ่านระบบบันทึกค่าให้เองอยู่แล้วและไม่ส่งบรรทัดนี้"
)
WARN_WRITE_MEMORY = (
    "write memory ต้องสั่งในโหมด privileged EXEC (หลัง end) และจะเขียนทับ startup-config เดิม "
    "— การ Deploy ผ่านระบบบันทึกค่าให้เองอยู่แล้วและไม่ส่งบรรทัดนี้"
)
WARN_HUAWEI_VTY_RANGE = "Huawei หลายรุ่นรองรับ VTY 0–4 (บางรุ่นถึง 0–14) กรุณาตรวจสอบช่วง VTY บนอุปกรณ์ปลายทาง"
ADVISORY_DHCP_ENABLE = "แนะนำ: Huawei ต้องเปิดบริการ DHCP ก่อนเปิด DHCP snooping ด้วยคำสั่ง: dhcp enable"
WARN_DHCP_ENABLE = (
    "Huawei ต้องสั่ง dhcp enable ก่อน dhcp snooping enable — ระบบไม่เติมคำสั่งนี้ให้เอง "
    "(เขียนไว้เป็นคำแนะนำใน Comment) กรุณาตรวจสอบบนอุปกรณ์ปลายทาง"
)
WARN_DHCP_SNOOPING_VLAN_UNDECLARED = (
    "VLAN นี้ไม่ได้ประกาศไว้ในไฟล์ต้นทาง — บน Huawei คำสั่ง vlan <id> จะสร้าง VLAN ขึ้นใหม่ กรุณาตรวจสอบ"
)
WARN_TWO_TUPLE_PORTS = (
    "ระบบคงหมายเลขพอร์ต 2 หลักตามต้นฉบับ (เช่น 0/1) — หากอุปกรณ์ปลายทางเป็นสวิตช์หรือเราเตอร์ Huawei "
    "รุ่นที่ใช้พอร์ต 3 หลัก (เช่น S5700, S6700, AR) กรุณาปรับเป็นรูปแบบ 0/0/1 ก่อนนำไปใช้งาน"
)


WARN_BANNER_MOTD_SHELL = (
    "Cisco banner motd แสดงก่อนการ Login ส่วน Huawei header shell information แสดงหลัง Login สำเร็จ "
    "— ระบบแปลงคู่กันตามกฎ กรุณาตรวจสอบว่าเวลาแสดงข้อความตรงกับที่ต้องการ"
)
WARN_BANNER_DELIMITER = (
    "อักขระคั่นข้อความ Banner เดิมใช้บนอุปกรณ์ปลายทางไม่ได้ (เป็นเครื่องหมาย Comment หรือปรากฏในข้อความ) "
    "ระบบจึงเปลี่ยนเป็นอักขระอื่นที่ไม่อยู่ในข้อความ กรุณาตรวจสอบ"
)
WARN_STP_RSTP = (
    "Cisco rapid-pvst รัน RSTP แยกต่อ VLAN แต่ Huawei stp mode rstp รัน Spanning Tree เดียวสำหรับทุก VLAN "
    "— Root Bridge และพอร์ตที่ถูก Block อาจเปลี่ยน กรุณาตรวจสอบ Topology"
)
WARN_STP_EDGE_DEFAULT = (
    "Cisco spanning-tree portfast default มีผลเฉพาะพอร์ต Access แต่ Huawei stp edged-port default มีผลกับทุกพอร์ต "
    "รวมถึง Trunk/Uplink — บน Huawei ควรตั้ง stp edged-port disable ที่พอร์ต Uplink/Trunk (ระบบไม่เติมให้เอง) "
    "โดยเฉพาะเมื่อเปิด stp bpdu-protection กรุณาตรวจสอบ"
)

# Banner delimiters that are safe on each target (never the target's comment marker).
_BANNER_DELIMITERS = {
    Vendor.HUAWEI_VRP: ('"', "%", "@", "~", "$", "&"),
    Vendor.CISCO_IOS_XE: ("#", "%", "@", "~", "$", "&", '"'),
}
_BANNER_HEADERS = {
    (Vendor.HUAWEI_VRP, "login"): "header login information",
    (Vendor.HUAWEI_VRP, "motd"): "header shell information",
    (Vendor.CISCO_IOS_XE, "login"): "banner login",
    (Vendor.CISCO_IOS_XE, "motd"): "banner motd",
}


def render_banner(w: LineWriter, banner: BannerIR) -> None:
    """`<header> <d>first line` ... `last line<d>` (one line: `<header> <d>text<d>`), the
    display format both vendors read back. The source delimiter is kept when it is safe."""
    text = "\n".join(banner.lines)
    delimiter, warn = banner.delimiter, None
    if not delimiter or delimiter == w.marker or delimiter in text:
        candidates = [d for d in _BANNER_DELIMITERS[w.target] if d not in text]
        delimiter = candidates[0] if candidates else _BANNER_DELIMITERS[w.target][0]
        warn = WARN_BANNER_DELIMITER if banner.delimiter else None
    if banner.kind == "motd":
        warn = " | ".join(x for x in (warn, WARN_BANNER_MOTD_SHELL) if x)
    src = banner.source_lines[0] if banner.source_lines else None
    header = _BANNER_HEADERS[(w.target, banner.kind)]
    body = banner.lines or [""]
    texts = [f"{header} {delimiter}{body[0]}", *body[1:]]
    texts[-1] += delimiter
    for i, t in enumerate(texts):
        w.cmd(t, SyntaxCategory.TRANSFORM, src, warn if i == 0 else None)


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
