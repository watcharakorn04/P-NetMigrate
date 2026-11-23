"""Device inventory (proposal §2.3.1 module 3).

A register only (3.3): the system never connects to a device to read values from it.
Fields per 3.1: name, IP, vendor, OS version, SSH port, location, status — plus the hardware
model used by the compatibility check (module 8.1). There are NO credential columns: SSH
credentials are typed at deployment time and live only in memory.
"""

from __future__ import annotations

import ipaddress
from typing import Optional

from pydantic import BaseModel, Field, field_validator

from app.core.hardware import CATALOG
from app.core.ir import Vendor
from app.db import Database, utcnow

STATUSES = ("active", "inactive", "maintenance")


class DeviceIn(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    ip: str
    vendor: Vendor
    os_version: str = Field(default="", max_length=64)
    model: str = Field(default="", max_length=64)
    ssh_port: int = Field(default=22, ge=1, le=65535)
    location: str = Field(default="", max_length=128)
    status: str = "active"

    @field_validator("name", "os_version", "location", "model")
    @classmethod
    def _strip(cls, v: str) -> str:
        return v.strip()

    @field_validator("ip")
    @classmethod
    def _ipv4(cls, v: str) -> str:
        return str(ipaddress.IPv4Address(v.strip()))  # IPv4 only (proposal §2.3.2 item 3)

    @field_validator("status")
    @classmethod
    def _status(cls, v: str) -> str:
        if v not in STATUSES:
            raise ValueError(f"status must be one of {', '.join(STATUSES)}")
        return v

    def check_model(self) -> None:
        if self.model and (self.model not in CATALOG or CATALOG[self.model].vendor is not self.vendor):
            raise ValueError("model is not in the hardware catalogue for this vendor")


_COLUMNS = ("name", "ip", "vendor", "os_version", "model", "ssh_port", "location", "status")


def _row(r) -> dict:
    d = dict(r)
    d["model_name"] = CATALOG[d["model"]].display if d["model"] in CATALOG else ""
    return d


def list_devices(db: Database, q: Optional[str] = None, vendor: Optional[str] = None,
                 location: Optional[str] = None, status: Optional[str] = None) -> list[dict]:
    where, args = [], []
    if q:
        like = f"%{q.strip()}%"
        where.append("(name LIKE ? OR ip LIKE ? OR location LIKE ? OR vendor LIKE ? OR model LIKE ?)")
        args += [like] * 5
    if vendor in (v.value for v in Vendor):
        where.append("vendor = ?")
        args.append(vendor)
    if location:
        where.append("location LIKE ?")
        args.append(f"%{location.strip()}%")
    if status in STATUSES:
        where.append("status = ?")
        args.append(status)
    sql = "SELECT * FROM devices" + (" WHERE " + " AND ".join(where) if where else "") + " ORDER BY name COLLATE NOCASE"
    with db.connect() as conn:
        return [_row(r) for r in conn.execute(sql, args).fetchall()]


def get_device(db: Database, device_id: int) -> Optional[dict]:
    with db.connect() as conn:
        r = conn.execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()
    return _row(r) if r else None


def create_device(db: Database, data: DeviceIn) -> dict:
    data.check_model()
    now = utcnow()
    values = [getattr(data, c).value if c == "vendor" else getattr(data, c) for c in _COLUMNS]
    with db.connect() as conn:
        cur = conn.execute(
            f"INSERT INTO devices ({', '.join(_COLUMNS)}, created_at, updated_at) VALUES ({', '.join('?' * (len(_COLUMNS) + 2))})",
            values + [now, now],
        )
        new_id = cur.lastrowid
    return get_device(db, int(new_id))  # type: ignore[return-value]


def update_device(db: Database, device_id: int, data: DeviceIn) -> Optional[dict]:
    data.check_model()
    values = [getattr(data, c).value if c == "vendor" else getattr(data, c) for c in _COLUMNS]
    with db.connect() as conn:
        n = conn.execute(
            f"UPDATE devices SET {', '.join(c + ' = ?' for c in _COLUMNS)}, updated_at = ? WHERE id = ?",
            values + [utcnow(), device_id],
        ).rowcount
    return get_device(db, device_id) if n else None


def delete_device(db: Database, device_id: int) -> bool:
    with db.connect() as conn:
        return conn.execute("DELETE FROM devices WHERE id = ?", (device_id,)).rowcount > 0
