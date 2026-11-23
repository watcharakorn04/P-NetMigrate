# NetMigrate

**ระบบการตั้งค่าอุปกรณ์เครือข่ายแบบหลายผู้ผลิต**
*Network Configuration Conversion System for Multi-Vendor Migration*

ระบบแปลงไฟล์ตั้งค่าอุปกรณ์เครือข่ายแบบสองทิศทาง **Cisco IOS-XE ⇄ Huawei VRP** สำหรับโปรโตคอล **IPv4**
พัฒนาตามข้อเสนอโครงงานพิเศษ [`691114-ทก1`](691114-ทก1.md) (ทก.01) ซึ่งเป็นเอกสารอ้างอิงหลักของโครงงาน

> **สถานะ:** พัฒนาครบทั้ง 8 โมดูลแล้ว (Milestone 1–5) และผ่านการทดสอบ `pytest` ทั้งหมด **596 รายการ**

---

## สารบัญ

1. [ภาพรวมระบบ](#1-ภาพรวมระบบ-project-overview)
2. [ความสามารถทั้ง 8 โมดูล](#2-ความสามารถทั้ง-8-โมดูล-8-core-modules)
3. [ระดับกฎการแปลงและมาตรการความปลอดภัย](#3-ระดับกฎการแปลงและมาตรการความปลอดภัย-rule-tiers--security-guardrails)
4. [เทคโนโลยีที่ใช้](#4-เทคโนโลยีที่ใช้-tech-stack)
5. [การติดตั้งและเริ่มต้นใช้งาน](#5-การติดตั้งและเริ่มต้นใช้งาน-installation--quick-start)
6. [การทดสอบอัตโนมัติ](#6-การทดสอบอัตโนมัติ-automated-testing)
7. [โครงสร้างโปรเจกต์](#7-โครงสร้างโปรเจกต์-repository-structure)

---

## 1. ภาพรวมระบบ (Project Overview)

NetMigrate ช่วยผู้ดูแลระบบย้ายการตั้งค่าระหว่างอุปกรณ์ Cisco และ Huawei โดยไม่ต้องแปลงคำสั่งด้วยมือ
ระบบรองรับเฉพาะคู่ผู้ผลิต Cisco IOS-XE ⇄ Huawei VRP และเฉพาะ IPv4 เท่านั้น

### สถาปัตยกรรม 3 ชั้น: Parser → IR → Renderer

```
raw text ─► strip_secrets ─► Parser (แยกตามผู้ผลิต) ─► IR (ไม่ผูกกับผู้ผลิต) ─► Renderer (แยกตามผู้ผลิต) ─► บรรทัดผลลัพธ์พร้อมป้ายกำกับ
                                   │
                                   └─► (hybrid / ai_only / ผู้ใช้เลือกเอง) บรรทัดที่กรองความลับแล้ว ─► AI ─► "มาจาก AI ต้องตรวจสอบก่อนใช้"
```

| ชั้น | หน้าที่ |
|---|---|
| **Parser** (`app/core/parsers/`) | อ่านคำสั่งของผู้ผลิตต้นทาง แล้วแปลงเป็น IR โดยไม่สร้างคำสั่งของปลายทาง |
| **Intermediate Representation (IR)** (`app/core/ir.py`) | เก็บ *เจตนา* ของการตั้งค่า (ไม่ใช่ข้อความ) การตรวจ round-trip ทำที่ระดับ IR |
| **Renderer** (`app/core/renderers/`) | สร้างคำสั่งของผู้ผลิตปลายทางจาก IR โดยไม่อ่านข้อความต้นฉบับ |

ความแตกต่างของไวยากรณ์แบ่งเป็น 3 ประเภท:

- **D (Direct):** แปลงคำต่อคำ / บรรทัดต่อบรรทัด
- **T (Transform):** 1 บรรทัด → 1 บรรทัด แต่รูปแบบอาร์กิวเมนต์เปลี่ยน เช่น `10,20,30-35` ⇄ `10 20 30 to 35`
- **S (Structural):** โครงสร้างบล็อกหรือลำดับเปลี่ยน เช่น OSPF

### Pre-scan และโหมดการแปลง 3 แบบ

ก่อนแปลงทุกครั้ง ระบบจะรัน **Pre-scan** (`POST /api/prescan`) ซึ่งไม่แปลงอะไรเลย แต่รายงานเปอร์เซ็นต์ที่กฎครอบคลุม
และเลขบรรทัดที่กฎไม่รองรับ เพื่อให้ผู้ใช้เลือกโหมดได้

| โหมด | พฤติกรรม |
|---|---|
| `hybrid` (**ค่าเริ่มต้น**) | ใช้กฎก่อน เรียก AI เฉพาะเมื่อไม่มีกฎรองรับ กฎรายงานว่าแปลงไม่ครบ หรือหัวบล็อกตรงกับ `AI_COMPLEX_COMMANDS` |
| `rule_only` | ไม่ส่งข้อมูลออกภายนอกเลย บรรทัดที่แปลงไม่ได้จะถูกติดป้าย `แปลงไม่ได้` ให้ผู้ใช้เลือกส่ง AI เองภายหลัง |
| `ai_only` | ส่งทุกคำสั่ง (ที่กรองความลับแล้ว) ไปให้ AI |

หาก AI ใช้งานไม่ได้ ไม่มี API key หรือตอบผิดรูปแบบ ระบบจะคืนผลแบบ `rule_only` พร้อมข้อความแจ้งเตือน และไม่หยุดทำงาน
ระบบ**ไม่ใช้**ค่าความมั่นใจที่ AI รายงานเองในการตัดสินความน่าเชื่อถือ

### ป้ายกำกับที่มาของทุกบรรทัด (Per-line Provenance)

ทุกบรรทัดผลลัพธ์มีป้ายกำกับเพียงหนึ่งป้ายเสมอ ในทุกโหมด

| ป้ายกำกับ | ความหมาย | Deploy ได้ |
|---|---|---|
| `มาจากกฎ` | แปลงด้วยกฎแบบ deterministic | ✅ |
| `ระบบสร้างขึ้นเอง` | ระบบสร้างหรือกำหนดค่าเอง (เช่น บล็อก BGP ของ Huawei, เลข ACL ที่ระบบกำหนด) | ✅ (เฉพาะคำสั่ง ไม่รวมคอมเมนต์) |
| `มาจาก AI ต้องตรวจสอบก่อนใช้` | ผลจาก AI ต้องให้ผู้ดูแลตรวจสอบก่อน | ❌ |
| `แปลงไม่ได้` | ไม่รองรับ อยู่นอกขอบเขต หรือตั้งใจไม่แปลง | ❌ |
| `ไม่ต้องใช้คำสั่งนี้` | คำสั่งซ้ำซ้อนเพราะเป็นค่าเริ่มต้นของปลายทางอยู่แล้ว (เช่น `switchport trunk encapsulation dot1q` → Huawei) ซึ่งต่างจาก `แปลงไม่ได้` | ❌ |

ระบบไม่ทิ้งคำสั่งใดแบบเงียบ ๆ คำสั่งที่ไม่รองรับจะถูกเขียนเป็นคอมเมนต์ด้วยเครื่องหมายของผู้ผลิตปลายทาง
(`!` สำหรับ Cisco, `#` สำหรับ Huawei) พร้อมคำเตือนให้ตรวจสอบ

---

## 2. ความสามารถทั้ง 8 โมดูล (8 Core Modules)

| # | โมดูล | หน้าเว็บ | API หลัก |
|---|---|---|---|
| 1 | แปลง CLI / ไฟล์เดี่ยว (Single CLI / File Conversion) | `/` | `POST /api/prescan`, `POST /api/convert`, `POST /api/convert/selected`, `GET /api/health` |
| 2 | แปลงไฟล์แบบกลุ่ม (Batch File Conversion) | `/batch` | `POST /api/batch/convert`, `GET /api/batch/{batch_id}`, `GET /api/batch/{batch_id}/download` (zip + `migration_report.txt/.json`) |
| 3 | ทะเบียนอุปกรณ์ (Device Inventory) — บันทึกข้อมูลเท่านั้น ไม่อ่านค่าจากอุปกรณ์ | `/inventory` | `GET/POST /api/devices`, `GET/PUT/DELETE /api/devices/{device_id}` |
| 4 | นำค่าตั้งไปใช้งาน (Configuration Deployment) | `/deploy` | `POST /api/deploy/plan`, `POST /api/deploy/run`, `GET /api/deploy/jobs/{job_id}/events` (SSE log), `GET /api/deployments` |
| 5 | แดชบอร์ดและประวัติการตรวจสอบ (Dashboard & Audit History) | `/history`, `/history/{conversion_id}` | `GET /api/dashboard`, `GET /api/history`, **`GET /api/history/compare`** (เปรียบเทียบเวอร์ชันด้วย `difflib`), `GET /api/history/{id}/diff`, `POST /api/diff` |
| 6 | ตั้งค่าระบบและ UI (System Settings & UI) | `/settings` | `GET /api/settings/coverage` |
| 7 | วิเคราะห์ Topology และคำแนะนำการตั้งค่า (เทมเพลต 3 ระดับ) | `/topology` | `POST /api/topology/analyze`, `POST /api/topology/describe` (คำอธิบายจาก AI แบบกรองความลับ) |
| 8 | ตรวจสอบความเข้ากันได้ของฮาร์ดแวร์ (กฎล้วน 4 ผลตัดสิน) | `/hardware` | `GET /api/hardware/catalog`, `POST /api/hardware/check` |

**ส่วนติดต่อผู้ใช้ (UI)**

- รองรับ **2 ภาษา TH / EN** ทุกหน้า (`app/i18n.py`, `app/i18n_pages.py`)
- รองรับธีม **Light / Dark** (Tailwind `darkMode: "class"`) บันทึกใน `localStorage["netmigrate-theme"]` และใช้ก่อนการแสดงผลครั้งแรกใน `base.html`

---

## 3. ระดับกฎการแปลงและมาตรการความปลอดภัย (Rule Tiers & Security Guardrails)

### 3.1 ระดับกฎการแปลง 3 ระดับ (ตามความเสี่ยง)

| Tier | ไฟล์ | ครอบคลุม |
|---|---|---|
| 1 | `tier1_system.py`, `tier1_vlan.py`, `tier1_interface.py`, `tier1_routing.py`, `interface_names.py` | hostname, domain, เป้าหมาย NTP/syslog, VLAN และพอร์ต (access/trunk/STP edge), interface, static route, OSPFv2 |
| 2 | `tier2_services.py` | RIP, redistribute, default route, NTP, syslog, VTY/SSH (ไม่รวมคำสั่งบัญชีผู้ใช้) |
| 3 | `tier3_bgp_acl.py` | BGP, ACL พร้อม behavioural tests (ความเสี่ยงล้มเหลวแบบเงียบ) |

กฎแต่ละข้อจะรายงานว่าแปลงบล็อกได้ **ครบถ้วน** หรือไม่ (`complete: bool`) เพื่อให้ระบบตัดสินใจว่าจะส่งต่อให้ AI หรือไม่

### 3.2 มาตรการป้องกันพฤติกรรมเฉพาะของผู้ผลิต

- **BGP → Huawei:** Cisco เปิดใช้งาน neighbor อัตโนมัติ แต่ Huawei ไม่ทำ ระบบจึงสร้าง `ipv4-family unicast` + `peer <ip> enable`
  ให้ทุก neighbor โดยอัตโนมัติ ติดป้าย `ระบบสร้างขึ้นเอง` (หากไม่มี session จะขึ้นแต่ไม่แลกเปลี่ยน route) — นี่คือบล็อกคำสั่งเดียวที่ระบบเติมให้เอง
- **เลข ACL:** แมปตาม *ประเภท* ไม่คัดลอกเลขตรง ๆ

  | ประเภท | Cisco IOS-XE | Huawei VRP |
  |---|---|---|
  | Standard / Basic | 1–99 | 2000–2099 |
  | Standard / Basic | 1300–1999 | 2100–2799 |
  | Extended / Advanced | 100–199 | 3000–3099 |
  | Extended / Advanced | 2000–2699 | 3100–3799 |

  หัว ACL (`acl number …` / `ip access-list … <n>`) ที่ระบบกำหนดเลขเองจะติดป้าย `ระบบสร้างขึ้นเอง` พร้อมคำเตือนเรื่องเลขชนกัน
  Huawei 2800–2999 และ 3800–3999 ไม่มีเลขที่เทียบได้ใน Cisco จึงถูกระบุว่าแปลงไม่ได้
- **`stelnet server enable`:** Huawei ต้องใช้คำสั่งนี้เพื่อเปิด SSH แต่ระบบเขียนเป็น **คอมเมนต์แนะนำ** (`ADVISORY_STELNET`) เท่านั้น ไม่สร้างเป็นคำสั่ง
- **เลขพอร์ตไม่ถูกแปลง:** เปลี่ยนเฉพาะชื่อประเภท interface และเตือนเมื่อ slot ไม่ใช่ 0 (ยกเว้น interface เสมือน เช่น `Vlanif10` ⇔ `interface Vlan10`)
- **ค่าเริ่มต้นไม่ตรงกัน: เตือน ไม่เดาค่า** เช่น static route AD=1 (Cisco) กับ Preference=60 (Huawei), Serial HDLC กับ PPP, metric ของ redistribute
- **Hybrid ไม่ส่งคำสั่งกำกวมให้ AI อัตโนมัติ:** บรรทัดที่อยู่นอกขอบเขต ไม่รองรับ หรือตั้งใจไม่แปลง จะไม่ถูกส่งอัตโนมัติ
  (`rules/base.py::auto_ai_eligible`) เพราะการบอกว่า `แปลงไม่ได้` ปลอดภัยกว่าการได้คำสั่งที่ดูถูกต้องแต่ความหมายเพี้ยน
  อย่างไรก็ตาม ผู้ใช้ยัง **เลือกบรรทัดเหล่านี้ส่งให้ AI เองได้** ผ่าน `POST /api/convert/selected`
- **นอกขอบเขต** (เขียนเป็นคอมเมนต์พร้อมป้ายให้ตรวจสอบ ไม่ทิ้ง): IPv6, OSPFv3, RIPng, IS-IS, QoS policy, Route-Map/Route-Policy, VRF, Tunnel และ ATM interface

### 3.3 มาตรการความปลอดภัยภาคบังคับ (ทุกโหมด ทุกเส้นทางโค้ด)

**การกรองข้อมูลลับอัตโนมัติ (`strip_secrets`)** — ใช้กฎแบบ deterministic ใน `app/core/secret_stripper.py`

| จุด | มาตรการ |
|---|---|
| ก่อนบันทึกลง SQLite (`netmigrate.db`) | `history_service` เรียก `strip_secrets_keep_lines()` แทนบรรทัดที่มีรหัสผ่านด้วยข้อความแนะนำคงที่ (เลขบรรทัดยังตรงกัน) ตาราง `devices` ไม่มีคอลัมน์ username/password |
| ก่อนเรียก LLM API | ลบรหัสผ่าน ชื่อผู้ใช้ คีย์ และ community string ก่อนประกอบคำขอทุกครั้ง และ `ai_translator.py` กรองซ้ำอีกชั้น (defence in depth) |
| ผลลัพธ์จาก AI | ทุกบรรทัดถูกตรวจด้วย `contains_secret()` หากพบจะถูกแทนด้วย `ADVISORY_AI_SECRET` |
| ไฟล์ที่แปลงแล้ว | ไม่มีรหัสผ่าน hash หรือคีย์ ทั้งในคำสั่งและในคอมเมนต์ `!` / `#` มีเพียงคำแนะนำให้ตั้งค่าใหม่บนอุปกรณ์ปลายทาง |

**ความปลอดภัยในการ Deploy ด้วย Netmiko** (`app/services/deploy_service.py`)

- **โหมดจำลอง (Simulation / Dry-Run) เป็นค่าเริ่มต้น** และไม่เชื่อมต่ออุปกรณ์ใดเลย
- Deploy **เฉพาะ** บรรทัดคำสั่งที่มีป้าย `มาจากกฎ` และ `ระบบสร้างขึ้นเอง` เท่านั้น
- ตัดออกอัตโนมัติ: คอมเมนต์, `มาจาก AI ต้องตรวจสอบก่อนใช้`, `แปลงไม่ได้`, `ไม่ต้องใช้คำสั่งนี้` และบรรทัดรหัสผ่าน/ผู้ใช้
- แสดงรายการคำสั่งทั้งหมดและต้องได้รับการยืนยันจากผู้ใช้ก่อนเสมอ
- โหมดจริงใช้ได้กับอุปกรณ์ในทะเบียนที่ผู้ใช้ยืนยันว่าเป็น lab node ของ **EVE-NG** ที่สร้างเอง
- ข้อมูล SSH อยู่ **ในหน่วยความจำเท่านั้น** ไม่ถูกบันทึกใน log ไม่ถูกเขียนลง SQLite และถูกล้าง (`params.clear()`) ทันทีที่เปิด session ได้

**ความปลอดภัยของไฟล์ Batch `.zip`** (`app/services/batch_service.py`)

- อ่านไฟล์ zip ทั้งหมด **ในหน่วยความจำ** ไม่แตกไฟล์ลงดิสก์
- ป้องกัน **Zip Slip**: ปฏิเสธ absolute path, drive letter, `..` และเทคนิค backslash และลดชื่อไฟล์ผลลัพธ์ให้เหลือ basename ที่ปลอดภัย
- รับเฉพาะ `.txt` / `.cfg` ข้ามไฟล์ที่ **เข้ารหัส** และไฟล์ **ไบนารี** (มี NUL byte หรือถอดรหัสไม่ได้)
- ป้องกัน **Zip Bomb** ด้วย `MAX_ENTRIES`, `MAX_FILE_BYTES` (อ่านแบบจำกัดขนาดจริง ไม่เชื่อขนาดที่ประกาศ), `MAX_TOTAL_BYTES`, `MAX_RATIO`

---

## 4. เทคโนโลยีที่ใช้ (Tech Stack)

| ด้าน | เทคโนโลยี |
|---|---|
| ภาษา | Python 3.11+ |
| Web framework | FastAPI + Uvicorn, Jinja2 templates, `python-multipart` |
| UI | Tailwind CSS (CDN), vanilla JavaScript แยกตามหน้า (`app/static/js/`) |
| ฐานข้อมูล | SQLite ไฟล์เดียว ผ่าน `sqlite3` ของ stdlib (`app/db.py`) |
| การตั้งค่า | `pydantic-settings` + `python-dotenv` |
| LLM client | `httpx` เชื่อมต่อ endpoint ที่เข้ากันได้กับ **OpenAI** Chat Completions |
| SSH deploy | `netmiko` |
| การทดสอบ | `pytest` (+ Node harness เสริมใน `tests/js/`) |
| Stdlib อื่น ๆ | `difflib` (diff / เปรียบเทียบเวอร์ชัน), `zipfile` (batch), `ipaddress` |

---

## 5. การติดตั้งและเริ่มต้นใช้งาน (Installation & Quick Start)

ตัวอย่างคำสั่งสำหรับ **Windows PowerShell**

**1. Clone repository**

```powershell
git clone https://github.com/watcharakorn04/P-NetMigrate.git
cd P-NetMigrate
```

**2. สร้าง virtual environment และติดตั้ง dependencies**

```powershell
python -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
```

**3. ตั้งค่าไฟล์ `.env`**

```powershell
copy .env.example .env
```

| ตัวแปร | ค่าเริ่มต้น | หน้าที่ |
|---|---|---|
| `LLM_API_KEY` | *(ว่าง)* | หากว่าง → AI ใช้ไม่ได้ → ระบบใช้ `rule_only` อัตโนมัติพร้อมแจ้งเตือน |
| `LLM_API_BASE_URL` | `https://api.openai.com/v1` | base URL ที่เข้ากันได้กับ OpenAI (ระบบ POST ไปที่ `{base}/chat/completions`) |
| `LLM_MODEL` | `gpt-4o-mini` | ชื่อโมเดล |
| `LLM_TIMEOUT_SECONDS` | `60` | เวลารอสูงสุดของคำขอ |
| `AI_COMPLEX_COMMANDS` | *(ว่าง)* | prefix ของหัวบล็อกที่ hybrid จะส่ง AI เสมอ คั่นด้วยจุลภาค เช่น `router bgp,bgp` |
| `DATABASE_URL` | `sqlite:///./netmigrate.db` | ไฟล์ SQLite |

ตัวอย่าง **OpenAI**:

```
LLM_API_KEY=<OpenAI API key>
LLM_API_BASE_URL=https://api.openai.com/v1
LLM_MODEL=gpt-4o-mini
```

ตัวอย่าง **Google AI Studio / Gemini** (ผ่าน endpoint ที่เข้ากันได้กับ OpenAI):

```
LLM_API_KEY=<AI Studio key>
LLM_API_BASE_URL=https://generativelanguage.googleapis.com/v1beta/openai
LLM_MODEL=gemini-2.5-flash
```

> หากไม่ใส่ `LLM_API_KEY` ระบบยังใช้งานได้ตามปกติในโหมด `rule_only` โดยอัตโนมัติ
> ห้าม commit ไฟล์ `.env` หรือไฟล์ config ของอุปกรณ์จริงที่มีข้อมูลลับ

**4. รันเซิร์ฟเวอร์**

```powershell
.venv\Scripts\python -m uvicorn app.main:app --reload
```

เปิดเบราว์เซอร์ที่ <http://127.0.0.1:8000> (มีไฟล์ตัวอย่างใน `app/static/samples/`)

---

## 6. การทดสอบอัตโนมัติ (Automated Testing)

```powershell
.venv\Scripts\python -m pytest -v
```

- ปัจจุบันผ่านการทดสอบทั้งหมด **596 รายการ**
- `tests/conftest.py` สร้างไฟล์ SQLite ชั่วคราวแยกให้ทุกการทดสอบ ฐานข้อมูลจริง `netmigrate.db` **จะไม่ถูกแตะต้อง**
- การทดสอบ AI ใช้ translator จำลอง ไม่เรียก LLM endpoint จริง
- มีการทดสอบยืนยันว่าไม่มีข้อมูลลับรั่วไหล (ข้อความที่ส่ง AI, ไฟล์ผลลัพธ์รวมคอมเมนต์, แถวใน SQLite, payload สำหรับ deploy)
- การทดสอบ JS ใน `tests/js/` จะถูกข้ามอัตโนมัติหากไม่ได้ติดตั้ง Node.js

---

## 7. โครงสร้างโปรเจกต์ (Repository Structure)

```
691114-ทก1.md               ข้อเสนอโครงงานที่อนุมัติแล้ว (เอกสารอ้างอิงหลัก)
CLAUDE.md  README.md
requirements.txt  pytest.ini  .env.example  .gitignore
app/
  main.py                   แอป FastAPI: route ของโมดูล 1 + รวม router อื่น
  config.py                 การตั้งค่า (pydantic-settings, .env)
  db.py                     sqlite3: ตาราง conversions, devices, deployments, batch_skipped
  deps.py                   dependency get_db / get_translator
  web.py                    Jinja2, เมนูนำทาง, ภาษา, ASSET_VERSION
  i18n.py  i18n_pages.py    ข้อความ UI ภาษาไทย / อังกฤษ
  routes/                   router ของโมดูล 2–8
    batch.py  deploy.py  hardware.py  history.py  inventory.py  settings_page.py  topology.py
  core/
    ir.py                   IR และ enum (Vendor, ConversionMode, SyntaxCategory, Provenance)
    engine.py               pipeline: strip → parse → rules/AI → render
    prescan.py              คำนวณ % ความครอบคลุมและรายการบรรทัดที่ไม่รองรับ
    secret_stripper.py      ตัวกรองข้อมูลลับ (security gate)
    vendor_detect.py        ตรวจจับ Cisco / Huawei อัตโนมัติ
    diff.py                 diff ก่อน/หลัง และเปรียบเทียบเวอร์ชันด้วย difflib
    topology.py  advisory.py  โมดูล 7: วิเคราะห์ topology และเทมเพลต 3 ระดับ
    hardware.py             โมดูล 8: แคตตาล็อกและตรวจความเข้ากันได้ 4 ผลตัดสิน
    parsers/                Parser แยกตามผู้ผลิต (cisco_iosxe.py, huawei_vrp.py)
    renderers/              Renderer แยกตามผู้ผลิต (cisco_iosxe.py, huawei_vrp.py)
    rules/                  กฎการแปลง Tier 1–3 และ interface_names.py
  services/
    ai_translator.py        LLM client (httpx) + กรองข้อมูลลับขาเข้า/ขาออก
    mode_selector.py        เลือกโหมด hybrid / rule_only / ai_only
    batch_service.py        จัดการ zip ในหน่วยความจำ + รายงาน batch
    deploy_service.py       กรองคำสั่ง deploy, โหมดจำลอง, งาน Netmiko, SSE log
    history_service.py      ประวัติที่กรองข้อมูลลับแล้ว + สถิติแดชบอร์ด
    inventory_service.py    CRUD ทะเบียนอุปกรณ์
  templates/                เทมเพลต Jinja2 ของทุกหน้า
  static/
    js/                     สคริปต์ประจำแต่ละหน้า
    samples/                cisco_sample.txt, huawei_sample.txt
tests/
  conftest.py               SQLite ชั่วคราวต่อการทดสอบ
  helpers.py
  fixtures/                 ไฟล์ config ตัวอย่าง Cisco / Huawei (tier1, tier23, with_secrets)
  js/convert_harness.js     Node harness ทดสอบสคริปต์หน้าเว็บจริง
  test_*.py                 ชุดทดสอบ: secret stripper, prescan, กฎ Tier 1–3, AI/hybrid,
                            batch, deploy, history, inventory/hardware, topology/settings, web UI
```
