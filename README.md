# Cloud Forensics Evidence Collector
### Project PRJN26-141 — Energy Sector Breach Investigation

A lightweight, fully self-contained Python CLI tool for digital forensic evidence collection in cloud-mounted storage environments. Designed for first-responder use in OT/ICS breach scenarios — no internet access, no pip installs, no external dependencies.

---

## Project Overview

During the PRJN26-141 incident, an unauthorised actor (IP `10.7.8.234`) bypassed network controls and accessed sensitive energy infrastructure files including SCADA configurations, billing records, and meter data. This tool was built to:

- **Collect** cryptographic evidence (MD5 + SHA-256) for every file in a target directory
- **Detect tampering** by comparing current file hashes against a known-good baseline
- **Report** findings as a timestamped CSV (for SIEM/legal chain-of-custody) and HTML dashboard (for analysts)
- **Log** every action to a persistent audit trail (`forensic_log.txt`)

---

## Project Structure

```
cloud-forensics-energy/
├── forensic_tool.py          # Main CLI entry point (argparse)
├── scanner.py                # Recursive directory scan + metadata collection
├── hasher.py                 # MD5 + SHA-256 hashing (streaming, memory-safe)
├── comparator.py             # Baseline creation, loading, and diff logic
├── report_generator.py       # CSV evidence report + HTML dashboard generation
├── logger_config.py          # Centralised logging (file + console)
├── requirements.txt          # Standard library only — nothing to install
├── README.md                 # This file
├── sample_energy_data/       # 13 realistic dummy files simulating an energy company
│   ├── meter_readings_jan2026.csv
│   ├── meter_readings_feb2026.csv
│   ├── billing_records_Q1_2026.csv
│   ├── grid_config.ini
│   ├── substation_config.xml
│   ├── system_events.log
│   ├── access_log.log
│   ├── anomaly_report.csv
│   ├── power_forecast.csv
│   ├── maintenance_schedule.csv
│   ├── employee_access.csv
│   ├── network_topology.json
│   ├── emergency_contacts.txt
│   ├── scada_backup.log
│   └── api_config.cfg
└── baselines/                # Auto-created — stores baseline JSON files
```

---

## Requirements

- Python **3.10 or later**
- No external packages — uses only the standard library:
  `os`, `sys`, `pathlib`, `hashlib`, `csv`, `json`, `argparse`, `logging`, `datetime`, `typing`

---

## Quick Start

### 1. Create a baseline (known-good snapshot)

```bash
python forensic_tool.py baseline --path sample_energy_data/
```

**What it does:** Hashes every file in the directory with MD5 + SHA-256, saves the results to `baselines/baseline_<path>.json`. This is your forensic reference point.

**Sample output:**
```
2026-04-06 14:30:11 [INFO    ] Scanning directory: sample_energy_data
2026-04-06 14:30:11 [INFO    ] Scan complete — 15 file(s) collected from 'sample_energy_data'
2026-04-06 14:30:11 [INFO    ] Baseline saved → baselines/baseline_...json  (15 files indexed)

[+] Baseline created successfully!
    Files indexed : 15
    Baseline file : baselines/baseline_..._sample_energy_data.json
    Timestamp     : 2026-04-06 14:30:11
    Log file      : forensic_log.txt
```

---

### 2. Scan and generate evidence reports

```bash
python forensic_tool.py scan --path sample_energy_data/
```

Compares current file state against the baseline (if one exists) and generates:
- `evidence_report_2026-04-06_143022.csv` — structured evidence log
- `forensic_dashboard_2026-04-06_143022.html` — interactive browser dashboard

**Optional: output reports to a specific folder:**
```bash
python forensic_tool.py scan --path sample_energy_data/ --output reports/
```

**Sample output (with tampering detected):**
```
[+] Scan complete!
    Total files   : 15
    Flagged files : 3
      NEW         : 0
      MODIFIED    : 2
      DELETED     : 1
    CSV Report    : evidence_report_2026-04-06_143022.csv
    HTML Dashboard: forensic_dashboard_2026-04-06_143022.html
    Log file      : forensic_log.txt

[!] WARNING: 3 suspicious file(s) detected. Review the HTML dashboard.
```

---

### 3. Compare against baseline (console-only diff)

```bash
python forensic_tool.py compare --path sample_energy_data/
```

Prints a detailed change summary to stdout. Add `--report` to also generate CSV + HTML:

```bash
python forensic_tool.py compare --path sample_energy_data/ --report
```

**Sample output:**
```
[+] Comparison complete!
    Baseline from : 2026-04-06 14:30:11
    Total files   : 15
    Flagged       : 3

  [MODIFIED FILES — 2]
    ~ /path/to/sample_energy_data/grid_config.ini
      Current SHA256  : a4f2e1c9b3d7f6e8...
      Baseline SHA256 : d8f1a2c4e7b9f3d1...
    ~ /path/to/sample_energy_data/billing_records_Q1_2026.csv
      Current SHA256  : 7b3c9f2e1a4d8e6f...
      Baseline SHA256 : 2c4e8a1f9b7d3c5e...

  [DELETED FILES — 1]
    - /path/to/sample_energy_data/network_topology.json
```

---

## Output Files

### CSV Evidence Report

`evidence_report_YYYY-MM-DD_HHMMSS.csv`

| Column | Description |
|--------|-------------|
| Status | UNCHANGED / NEW / MODIFIED / DELETED |
| Filename | File name only |
| File Path | Full absolute path |
| Extension | File extension |
| Size (Bytes) | File size in bytes |
| Created | Creation timestamp |
| Modified | Last modified timestamp |
| Accessed | Last accessed timestamp |
| MD5 | MD5 hex digest |
| SHA256 | SHA-256 hex digest |

The first 7 rows contain a summary block (scan time, total files, flagged counts) suitable for chain-of-custody documentation.

### HTML Dashboard

`forensic_dashboard_YYYY-MM-DD_HHMMSS.html`

Self-contained dark-themed dashboard (no internet required). Features:

- **Alert banner** — red warning when tampered files are found
- **Stat cards** — Total / Flagged / New / Modified / Deleted / Clean counts
- **Tampered files table** — isolated section with full MD5 + SHA-256 for flagged items
- **All files table** — sortable by any column (click headers), colour-coded by status
- **Zero dependencies** — all CSS and JS are inlined; opens in any browser

### Baseline JSON

`baselines/baseline_<sanitised_path>.json`

```json
{
  "created": "2026-04-06 14:30:11",
  "target_directory": "/absolute/path/to/scan",
  "file_count": 15,
  "files": {
    "/absolute/path/file.csv": {
      "md5": "abc123...",
      "sha256": "def456...",
      "size_bytes": 4821,
      "modified": "2026-03-14 16:20:01"
    }
  }
}
```

### Forensic Log

`forensic_log.txt` — append-only, timestamped log of all actions:

```
2026-04-06 14:30:11 [INFO    ] === Forensic Tool Started  |  Command: baseline ===
2026-04-06 14:30:11 [INFO    ] Scanning directory: sample_energy_data
2026-04-06 14:30:11 [DEBUG   ] Scanned [      2341 B] .../grid_config.ini
2026-04-06 14:30:11 [INFO    ] Scan complete — 15 file(s) collected
2026-04-06 14:30:11 [INFO    ] Baseline saved → baselines/baseline_...json
```

---

## Demo Workflow (Simulating a Breach)

```bash
# Step 1 — Establish known-good baseline
python forensic_tool.py baseline --path sample_energy_data/

# Step 2 — Simulate attacker modifications
#   (Manually edit grid_config.ini or delete a file to simulate tampering)

# Step 3 — Run forensic scan and generate reports
python forensic_tool.py scan --path sample_energy_data/ --output reports/

# Step 4 — Open the HTML dashboard in your browser
#   Open: reports/forensic_dashboard_YYYY-MM-DD_HHMMSS.html

# Step 5 — Compare details in console
python forensic_tool.py compare --path sample_energy_data/ --report
```

---

## Sample Data Description

The `sample_energy_data/` directory contains 15 files simulating a real energy company's cloud-mounted storage:

| File | Type | Contents |
|------|------|----------|
| `meter_readings_jan2026.csv` | CSV | Smart meter telemetry (kWh, voltage, power factor) |
| `meter_readings_feb2026.csv` | CSV | February meter readings continuation |
| `billing_records_Q1_2026.csv` | CSV | Customer invoices with payment status |
| `grid_config.ini` | INI | SCADA, alarm, and network configuration |
| `substation_config.xml` | XML | Transformer, feeder, and relay specifications |
| `system_events.log` | LOG | SCADA event stream including the breach indicators |
| `access_log.log` | LOG | Login/access audit trail showing attacker activity |
| `anomaly_report.csv` | CSV | IDS/SOC anomaly detections with severity ratings |
| `power_forecast.csv` | CSV | 5-day ahead load forecast with weather data |
| `maintenance_schedule.csv` | CSV | Work orders for transformers, relays, cables |
| `employee_access.csv` | CSV | Staff roles, clearances, and VPN access |
| `network_topology.json` | JSON | VLAN layout, firewall rules, critical host inventory |
| `emergency_contacts.txt` | TXT | On-call roster and escalation matrix |
| `scada_backup.log` | LOG | Backup job history including the forensic snapshot |
| `api_config.cfg` | CFG | Internal API endpoints and service credentials |

The `system_events.log`, `access_log.log`, `anomaly_report.csv`, and `scada_backup.log` files all contain embedded narrative around the breach timeline, making the demo self-explanatory for forensic training purposes.

---

## Use Cases

| Scenario | How to Use |
|----------|-----------|
| **First response** — cloud storage mounted, assess what the attacker touched | `scan` with no prior baseline — all files flagged NEW, full hash inventory generated |
| **Ongoing monitoring** — weekly integrity check of critical config files | `baseline` once → `compare` on schedule → alert on MODIFIED/DELETED |
| **Legal chain-of-custody** — document file state at time of acquisition | `scan --output evidence/` → timestamp-named CSV is court-ready artefact |
| **Incident report** — show management what changed and when | Open the HTML dashboard — shareable, self-contained, no software required |
| **Training exercise** — teach analysts what SCADA data looks like | Clone repo, run baseline, modify a file, run scan — observe tamper detection |

---

## Architecture Notes

```
forensic_tool.py   ← CLI / orchestration
    │
    ├── scanner.py         ← os.walk + pathlib.stat() + hasher.py
    ├── hasher.py          ← hashlib streaming (MD5 + SHA-256, 64 KiB chunks)
    ├── comparator.py      ← json baseline I/O + two-pass diff
    ├── report_generator.py ← csv.writer + inline HTML/CSS/JS string generation
    └── logger_config.py   ← logging.FileHandler + StreamHandler
```

All inter-module communication uses plain Python dicts and lists — no classes, no ORM, no frameworks. The tool is intentionally simple so it can be audited, modified, or ported by any Python developer in under an hour.

---

## Limitations

- **MD5 is included for legacy compatibility** (older SIEM tools), not as a security primitive. SHA-256 is the authoritative integrity check.
- On Windows, `st_ctime` reflects the last metadata change, not the original creation time. This is noted in `scanner.py`.
- Files locked by the OS (e.g., open log files on Windows) will produce `"ERROR"` hashes and a warning in the log — they are still listed in the report.
- The baseline path is derived from the absolute directory path. Moving the directory invalidates the baseline filename lookup.

---

*Cloud Forensics Automation Tool — PRJN26-141 | Python 3.10+ | Standard Library Only*
#   c l o u d - f o r e n s i c s - e n e r g y  
 