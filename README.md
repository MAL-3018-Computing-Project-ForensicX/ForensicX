# ForensicX: Unified Digital Forensic Analysis Framework

<div align="center">

**A modular, Python-based forensic pipeline that unifies endpoint logs, memory forensics, cloud metadata, and automated reporting into a single investigation workflow.**

[![Python](https://img.shields.io/badge/Python-3.12-blue?style=flat-square&logo=python)](https://www.python.org/)
[![Streamlit](https://img.shields.io/badge/Dashboard-Streamlit-FF4B4B?style=flat-square&logo=streamlit)](https://streamlit.io/)
[![License](https://img.shields.io/badge/License-Open%20Source-green?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Ubuntu%2022.04-orange?style=flat-square&logo=ubuntu)](https://ubuntu.com/)

**MAL3018 Computing Project** · Peninsula College / University of Plymouth  
**Azizul Hakim Hassan** (BSCS 2409162) · BSc (Hons) Computer Science (Cyber Security)  
[Demo Video](https://youtu.be/PhtzyQVNxeo) · [PebblePad Portfolio](https://v3.pebblepad.co.uk/spa/#/public/mtw79ZnjWtjRqhRhn6h3jynhcM)

</div>

---

## Overview

Modern ransomware attacks no longer operate within a single domain. Evidence of a breach is distributed across **Windows event logs**, **RAM**, **filesystem changes**, and **cloud storage** simultaneously. Existing open-source forensic tools are domain-specific — forcing investigators to switch between disconnected tools and manually correlate findings under time pressure.

**ForensicX** bridges this gap by integrating all evidence sources into one automated eight-stage pipeline:

| Stage | Module | Description |
|---|---|---|
| 0 | `orchestrator.py` | Configuration validation & path checks |
| 1 | `parse_evtx.py` | Load Sysmon, Volatility memory & snapshot events |
| 2 | `cloud_collect.py` | Collect Google Drive & OneDrive metadata via API |
| 3 | `cloud_behavior.py` | Cloud burst detection & behavioural risk scoring |
| 4 | `behavior.py` | Endpoint YARA scanning, entropy & process risk scoring |
| 5 | `correlate.py` | Unified cross-source event correlation by process\|PID |
| 6 | `cloud_endpoint_correlate.py` | Temporal cloud-to-endpoint attack chain linkage |
| 7 | `evidence.py` | SHA-256 hashing & chain-of-custody manifest |
| 8 | `report_builder.py` | PDF, JSON & TXT forensic report generation |

---

## Key Features

- **Multi-source ingestion** — Sysmon EVTX/JSON, Volatility 3 pslist, before/after filesystem snapshots, Google Drive (OAuth 2.0) and OneDrive (MSAL device code flow)
- **YARA ransomware detection** — Pattern matching against ransom note strings, Bitcoin references, `.locked` extensions
- **Shannon entropy analysis** — Files with entropy > 7.5 flagged as likely encrypted (ransomware indicator)
- **Cross-domain correlation** — Events grouped by `process_name|PID`, sorted chronologically across all sources
- **Cloud-to-endpoint attack chains** — Temporal proximity + filename similarity scoring with HIGH / MEDIUM / LOW confidence
- **Behavioural risk scoring** — Weighted indicators (entropy, burst, YARA, IOC, network, parent-child) → LOW / MEDIUM / HIGH / CRITICAL verdict
- **Evidence integrity** — SHA-256 hashes of all output artefacts + timestamped audit trail in `manifest.json`
- **Professional PDF report** — Cover page with risk badge, plain-English Sysmon EID translations, colour-coded risk tables, executive summary, recommended actions, glossary
- **9-page Streamlit dashboard** — Interactive investigation interface covering timeline, risk summary, process explorer, IOC hits, cloud attack chain, cloud risk, snapshot changes, EVTX parser, reports & evidence

---

## Compared to Existing Tools

| Tool | Endpoint | Memory | Cloud | Cross-Domain | Open Source |
|---|:---:|:---:|:---:|:---:|:---:|
| Autopsy | ✅ | ❌ | ❌ | ❌ | ✅ |
| Volatility 3 | ❌ | ✅ | ❌ | ❌ | ✅ |
| Velociraptor | ✅ | Partial | ❌ | ❌ | ✅ |
| Timesketch | Partial | ❌ | ❌ | ❌ | ✅ |
| Microsoft Sentinel | ✅ | ❌ | ✅ | Partial | ❌ |
| **ForensicX** | ✅ | ✅ | ✅ | ✅ | ✅ |

---

## Project Structure

```
fyp-forensics/
├── config/
│   ├── config.json                  ← Main pipeline configuration
│   └── google_drive_credentials.json
├── dashboards/
│   ├── dashboard.py                 ←  Streamlit entry point
│   └── pages/                       ← 9 dashboard pages
├── data/
│   ├── logs/                        ← Place sysmon_all.json here
│   ├── cloud/                       ← cloud_events.json (auto-generated)
│   └── memory_dumps/                ← Place memory.raw here
├── modules/
│   ├── orchestrator.py              ← 8-stage pipeline controller
│   ├── parse_evtx.py                ← EVTX → JSON parser
│   ├── correlate.py                 ← Correlation engine
│   ├── detection/
│   │   ├── behavior.py              ← YARA + entropy + risk scoring
│   │   └── cloud_behavior.py        ← Cloud anomaly detection
│   ├── cloud/
│   │   ├── cloud_collect.py         ← Cloud collection orchestrator
│   │   ├── google_drive.py          ← Google Drive API v3 (OAuth 2.0)
│   │   ├── onedrive.py              ← OneDrive Graph API (MSAL)
│   │   ├── cloud_normalize.py       ← Normalise cloud events to common schema
│   │   └── cloud_endpoint_correlate.py ← Cross-domain temporal linkage
│   ├── forensics/
│   │   └── evidence.py              ← SHA-256 hashing + manifest
│   └── threat/
│       └── enrich.py                ← VirusTotal + AbuseIPDB enrichment
├── report/                          ← All pipeline outputs written here
├── rules/
│   └── ransomware_rules.yar         ← YARA ransomware signatures
├── snapshots/
│   ├── before.json                  ← Pre-incident filesystem snapshot
│   └── after.json                   ← Post-incident filesystem snapshot
├── compare.py                       ← Standalone snapshot diff utility
├── snapshots.py                     ← Filesystem walker (SHA-256 + entropy)
└── requirements.txt
```

---

## Installation

### Prerequisites

- Ubuntu 22.04+ (analysis host)
- Python 3.12
- 8 GB RAM minimum, 10 GB free disk

### Setup

```bash
# 1. Clone the repository
git clone https://github.com/MAL-3018-Computing-Project-ForensicX/ForensicX.git
cd ForensicX/fyp-forensics

# 2. Create and activate virtual environment
python3 -m venv myenv
source myenv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Launch the dashboard
streamlit run dashboards/dashboard.py
```

Open your browser at `http://localhost:8501`.

> **Tip:** Keep the terminal open while using the dashboard. Each new session requires `source myenv/bin/activate` then `streamlit run dashboards/dashboard.py`.

---

## Quick Start

### Option A — Dashboard (Recommended)

1. Place your evidence files:
   - Sysmon JSON → `data/logs/sysmon_all.json`
   - Memory dump → `data/memory_dumps/memory.raw`
2. Open the dashboard and use **EVTX Parser** to convert `.evtx` files
3. Use **Snapshot Manager** to take before/after folder snapshots
4. On the home page, tick the data sources you have and click **Run Forensic Analysis**
5. View results across the 9 dashboard pages; download reports from **Reports & Evidence**

### Option B — CLI

```bash
# Full analysis with all sources
python modules/orchestrator.py \
  --sysmon data/logs/sysmon_all.json \
  --before snapshots/before.json \
  --after snapshots/after.json

# Skip cloud collection (offline / no credentials)
python modules/orchestrator.py \
  --sysmon data/logs/sysmon_all.json \
  --before snapshots/before.json \
  --after snapshots/after.json \
  --skip-cloud

# Snapshot comparison only
python compare.py snapshots/before.json snapshots/after.json

# Convert EVTX to JSON (specific Event IDs)
python modules/parse_evtx.py data/logs/sysmon.evtx data/logs/sysmon_all.json 1 3 11
```

---

## Pipeline Outputs

All outputs are written to the `report/` directory:

| File | Format | Description |
|---|---|---|
| `correlation.pdf` | PDF | Main forensic report — cover, risk badge, executive summary, colour-coded process tables, cloud attack chains, glossary |
| `correlation.txt` | TXT | Plain-text version — suitable for archiving or incident tickets |
| `forensic_report.json` | JSON | Structured report data for external tooling |
| `correlation.json` | JSON | Raw process-event correlation (input for dashboard pages) |
| `endpoint_risk_summary.json` | JSON | Per-process risk scores and overall verdict |
| `cloud_risk_summary.json` | JSON | Cloud account burst analysis and risk levels |
| `cloud_endpoint_correlations.json` | JSON | All cloud-to-endpoint attack chain findings |
| `manifest.json` | JSON | SHA-256 hashes + audit trail for chain-of-custody |
| `pipeline.log` | TXT | Full execution log — first place to check if something goes wrong |

---

## Cloud Setup (First-Time Only)

### Google Drive

1. Go to [Google Cloud Console](https://console.cloud.google.com) → create a project → enable **Google Drive API**
2. Create an OAuth 2.0 Client ID (Desktop app) and download the credentials JSON
3. Rename it `google_drive_credentials.json` and place it in `config/`
4. Set `"google_drive": { "enabled": true }` in `config/config.json`
5. On the first run, a browser window opens for sign-in — token is saved automatically

### OneDrive

The `client_id` is pre-configured in `config/config.json`. On first run, the terminal displays a device code URL — visit it in a browser to authenticate. Token is cached to `config/onedrive_token.json` for future runs.

---

## Behaviour Risk Scoring

The `behavior.py` module applies a weighted scoring system to every process:

| Indicator | Points |
|---|---|
| Snapshot file added | +10 |
| Snapshot file modified | +10 |
| Shannon entropy > 7.5 (encrypted file) | +30 |
| YARA rule match | +40 |
| IOC hash match | +50 |
| IOC IP/domain match | +20 |
| External network connection | +15 |
| Suspicious parent-child process (e.g. Office → PowerShell) | +25 |
| File operation burst (≥10 ops in 5 minutes) | +30 |

**Risk levels:** LOW (0–39) · MEDIUM (40–79) · HIGH (80–139) · CRITICAL (140+)

---

## Cloud-to-Endpoint Correlation Confidence

| Confidence | Condition |
|---|---|
| **HIGH** | Time gap ≤ 10 seconds **AND** filename similarity ≥ 80% |
| **MEDIUM** | Time gap ≤ 60 seconds **OR** filename similarity ≥ 50% |
| **LOW** | Any match within the 10-minute correlation window |

---

## Testing

69 functional test cases were executed across all modules — all passed.

```bash
# Run the behaviour analysis self-test
python modules/detection/behavior.py

# Run the formal unit test suite
python -m pytest modules/tests/test_behavior.py -v
```

| Category | Test Cases | Status |
|---|:---:|:---:|
| Installation & setup | 5 | ✅ PASS |
| EVTX log parsing | 6 | ✅ PASS |
| Filesystem snapshot | 6 | ✅ PASS |
| Volatility memory integration | 4 | ✅ PASS |
| Endpoint behaviour scoring | 8 | ✅ PASS |
| YARA ransomware detection | 4 | ✅ PASS |
| Correlation engine | 6 | ✅ PASS |
| Cloud metadata collection | 5 | ✅ PASS |
| Cloud behaviour analysis | 5 | ✅ PASS |
| Cloud-endpoint correlation | 5 | ✅ PASS |
| Evidence integrity | 4 | ✅ PASS |
| Report generation | 5 | ✅ PASS |
| Streamlit dashboard | 6 | ✅ PASS |
| **Total** | **69** | **✅ All Pass** |

---

## Dependencies

Core libraries (see `requirements.txt` for full list):

```
streamlit
python-evtx
lxml
yara-python
google-api-python-client
google-auth-oauthlib
msal
requests
reportlab
pandas
```

---

## Legal & Ethical Notice

ForensicX is designed exclusively for **authorised digital forensic investigation**. Use of this framework against systems or accounts without lawful authority may violate the **Computer Crimes Act 1997 (Malaysia)**, **PDPA 2010**, and **GDPR**. All API access uses read-only scopes in compliance with data minimisation principles. Risk scores are produced by a deterministic algorithm and must be reviewed by a qualified security analyst before any action is taken.

---

## Future Enhancements

- Machine learning anomaly detection layer on the correlation timeline
- SQLite / document database for persistent multi-run case management
- Blockchain-based chain-of-custody verification
- Linux endpoint support via `auditd` or eBPF log collection
- Comprehensive automated regression test suite with CI/CD

---

## License

Open source — published as an academic research prototype. See repository for licensing details.

---

## Author

**Azizul Hakim Hassan**  
BSc (Hons) Computer Science (Cyber Security), Year 3  
Peninsula College / University of Plymouth  
bscs2409162@peninsulamalaysia.edu.my  
azizul.hassan@students.plymouth.ac.uk

**Supervisor:** Nafisah Misriya Bt Shahul Hamid  
**Module Leader:** Eric Kong Kok Wah

---

<div align="center">
<sub>ForensicX · MAL3018 Computing Project · 2025–2026</sub>
</div>
