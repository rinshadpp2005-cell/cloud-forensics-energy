"""
report_generator.py
-------------------
Generates two output artefacts from a forensic scan:

  1. Timestamped CSV evidence report  — structured, importable into SIEM tools.
  2. Standalone HTML dashboard        — human-readable, sortable, self-contained.

Both outputs include a summary header and full per-file rows.  The HTML
dashboard highlights tampered files with colour-coded badges and supports
client-side column sorting with no external dependencies.
"""

import csv
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any


# ---------------------------------------------------------------------------
# CSV Report
# ---------------------------------------------------------------------------

def generate_csv_report(
    file_records:    List[Dict[str, Any]],
    new_files:       List[Dict[str, Any]],
    modified_files:  List[Dict[str, Any]],
    deleted_files:   List[Dict[str, Any]],
    output_dir: str = ".",
) -> str:
    """
    Write a timestamped CSV evidence report.

    The file starts with a plain-text summary block (scan metadata) followed
    by a standard header row and one data row per file.  Deleted files are
    appended at the end with status DELETED.

    Args:
        file_records:   All current scan records (including unchanged).
        new_files:      Records flagged NEW.
        modified_files: Records flagged MODIFIED.
        deleted_files:  Records flagged DELETED (not in current scan).
        output_dir:     Destination folder; created if it does not exist.

    Returns:
        Absolute path of the written CSV file.
    """
    os.makedirs(output_dir, exist_ok=True)

    ts       = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    filename = f"evidence_report_{ts}.csv"
    out_path = os.path.join(output_dir, filename)

    flagged  = len(new_files) + len(modified_files) + len(deleted_files)
    all_rows = list(file_records) + list(deleted_files)

    COLUMNS = [
        "Status", "Filename", "File Path", "Extension",
        "Size (Bytes)", "Created", "Modified", "Accessed",
        "MD5", "SHA256",
    ]

    with open(out_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)

        # ── Summary block ────────────────────────────────────────────────
        writer.writerow(["=== CLOUD FORENSICS EVIDENCE REPORT — PRJN26-141 ==="])
        writer.writerow(["Scan Time",        datetime.now().strftime("%Y-%m-%d %H:%M:%S")])
        writer.writerow(["Total Files",      len(file_records)])
        writer.writerow(["Flagged Files",    flagged])
        writer.writerow(["  NEW",            len(new_files)])
        writer.writerow(["  MODIFIED",       len(modified_files)])
        writer.writerow(["  DELETED",        len(deleted_files)])
        writer.writerow([])

        # ── Column headers ───────────────────────────────────────────────
        writer.writerow(COLUMNS)

        # ── Data rows ────────────────────────────────────────────────────
        for rec in all_rows:
            writer.writerow([
                rec.get("status",     "UNCHANGED"),
                rec.get("filename",   ""),
                rec.get("filepath",   ""),
                rec.get("extension",  ""),
                rec.get("size_bytes", ""),
                rec.get("created",    ""),
                rec.get("modified",   ""),
                rec.get("accessed",   ""),
                rec.get("md5",        ""),
                rec.get("sha256",     ""),
            ])

    return out_path


# ---------------------------------------------------------------------------
# HTML Dashboard
# ---------------------------------------------------------------------------

def _badge(status: str) -> str:
    """Return an HTML badge element for the given status string."""
    classes = {
        "NEW":       "badge-new",
        "MODIFIED":  "badge-modified",
        "DELETED":   "badge-deleted",
        "UNCHANGED": "badge-clean",
    }
    css = classes.get(status, "badge-clean")
    label = status if status != "UNCHANGED" else "CLEAN"
    return f'<span class="badge {css}">{label}</span>'


def _main_table_row(rec: Dict[str, Any]) -> str:
    status = rec.get("status", "UNCHANGED")
    row_css = {
        "NEW":      "row-new",
        "MODIFIED": "row-modified",
        "DELETED":  "row-deleted",
    }.get(status, "")

    md5_short = rec.get("md5", "")[:16] + "…" if rec.get("md5") else ""

    return (
        f'<tr class="{row_css}">'
        f'<td>{_badge(status)}</td>'
        f'<td title="{rec.get("filepath", "")}">{rec.get("filename", "")}</td>'
        f'<td class="mono">{rec.get("extension", "")}</td>'
        f'<td class="num">{rec.get("size_bytes", 0):,}</td>'
        f'<td>{rec.get("created", "")}</td>'
        f'<td>{rec.get("modified", "")}</td>'
        f'<td>{rec.get("accessed", "")}</td>'
        f'<td class="mono hash">{md5_short}</td>'
        f'</tr>'
    )


def _flagged_table_row(rec: Dict[str, Any]) -> str:
    status  = rec.get("status", "")
    row_css = {"NEW": "row-new", "MODIFIED": "row-modified", "DELETED": "row-deleted"}.get(status, "")
    sha_short = rec.get("sha256", "")[:40] + "…" if rec.get("sha256") else ""

    return (
        f'<tr class="{row_css}">'
        f'<td>{_badge(status)}</td>'
        f'<td title="{rec.get("filepath", "")}">{rec.get("filename", "")}</td>'
        f'<td class="mono hash">{rec.get("md5", "")}</td>'
        f'<td class="mono hash">{sha_short}</td>'
        f'<td>{rec.get("modified", "")}</td>'
        f'</tr>'
    )


def generate_html_report(
    file_records:    List[Dict[str, Any]],
    new_files:       List[Dict[str, Any]],
    modified_files:  List[Dict[str, Any]],
    deleted_files:   List[Dict[str, Any]],
    target_dir:      str,
    output_dir: str = ".",
) -> str:
    """
    Generate a self-contained, dark-themed HTML evidence dashboard.

    Features:
      - Summary stat cards
      - Alert banner when tampering is detected
      - Dedicated tampered-files table (colour-coded)
      - Full files table with client-side column sorting
      - Zero external dependencies (CSS + JS inlined)

    Args:
        file_records:   All current scan records.
        new_files:      NEW records.
        modified_files: MODIFIED records.
        deleted_files:  DELETED records.
        target_dir:     Path that was scanned (shown in dashboard).
        output_dir:     Destination folder.

    Returns:
        Absolute path of the written HTML file.
    """
    os.makedirs(output_dir, exist_ok=True)

    ts       = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    filename = f"forensic_dashboard_{ts}.html"
    out_path = os.path.join(output_dir, filename)

    scan_time   = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total       = len(file_records)
    flagged     = len(new_files) + len(modified_files) + len(deleted_files)
    clean_count = total - len(new_files) - len(modified_files)  # deleted not in current scan

    all_rows     = list(file_records) + list(deleted_files)
    flagged_recs = list(new_files) + list(modified_files) + list(deleted_files)

    main_rows    = "\n".join(_main_table_row(r)    for r in all_rows)
    flagged_rows = "\n".join(_flagged_table_row(r) for r in flagged_recs)

    alert_banner = (
        f'<div class="alert-box">'
        f'&#9888;&#xFE0F;  ALERT — {flagged} file(s) flagged as tampered, new, or deleted. '
        f'Immediate forensic review required.'
        f'</div>'
        if flagged > 0
        else '<div class="ok-box">&#10003;  All file hashes match the baseline. No tampering detected.</div>'
    )

    flagged_section = ""
    if flagged > 0:
        flagged_section = f"""
    <section>
      <h2 class="sec-alert">&#9888; Tampered / Suspicious Files ({flagged})</h2>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Status</th><th>Filename</th>
              <th>MD5</th><th>SHA-256 (partial)</th><th>Last Modified</th>
            </tr>
          </thead>
          <tbody>{flagged_rows}</tbody>
        </table>
      </div>
    </section>"""

    css = """
    :root {
      --bg:        #0d1117;
      --surface:   #161b22;
      --border:    #30363d;
      --text:      #c9d1d9;
      --muted:     #8b949e;
      --blue:      #58a6ff;
      --green:     #3fb950;
      --yellow:    #d29922;
      --red:       #f85149;
      --purple:    #bc8cff;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
           background: var(--bg); color: var(--text); padding: 28px 32px; line-height: 1.5; }

    /* ── Header ─────────────────────────────────────────────────────── */
    h1   { font-size: 1.65rem; color: var(--blue); margin-bottom: 2px; }
    .sub { font-size: 0.83rem; color: var(--muted); margin-bottom: 24px; }

    /* ── Banners ─────────────────────────────────────────────────────── */
    .alert-box, .ok-box {
      border-radius: 8px; padding: 13px 18px; margin-bottom: 22px; font-size: 0.9rem;
    }
    .alert-box { background: rgba(248,81,73,0.10); border: 1px solid rgba(248,81,73,0.45); color: var(--red);   }
    .ok-box    { background: rgba(63,185,80,0.08); border: 1px solid rgba(63,185,80,0.35); color: var(--green); }

    /* ── Stat cards ──────────────────────────────────────────────────── */
    .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(130px,1fr));
             gap: 12px; margin-bottom: 28px; }
    .card  { background: var(--surface); border: 1px solid var(--border); border-radius: 8px;
             padding: 16px; text-align: center; }
    .card .val   { font-size: 2rem; font-weight: 700; }
    .card .label { font-size: 0.7rem; color: var(--muted); margin-top: 4px;
                   text-transform: uppercase; letter-spacing: .06em; }
    .c-blue   .val { color: var(--blue);   }
    .c-red    .val { color: var(--red);    }
    .c-green  .val { color: var(--green);  }
    .c-yellow .val { color: var(--yellow); }

    /* ── Section headings ────────────────────────────────────────────── */
    section   { margin-bottom: 32px; }
    h2        { font-size: 1.05rem; padding-bottom: 8px; margin-bottom: 12px;
                border-bottom: 1px solid var(--border); }
    .sec-alert { color: var(--red); }

    /* ── Tables ──────────────────────────────────────────────────────── */
    .table-wrap { overflow-x: auto; border-radius: 8px; border: 1px solid var(--border); }
    table { width: 100%; border-collapse: collapse; font-size: 0.81rem; }
    thead th {
      background: #1c2128; color: var(--muted); text-align: left;
      padding: 10px 14px; font-weight: 600; text-transform: uppercase;
      font-size: 0.71rem; letter-spacing: .05em; cursor: pointer; white-space: nowrap;
    }
    thead th:hover { color: var(--text); }
    td { padding: 8px 14px; border-top: 1px solid var(--border); vertical-align: middle; }
    tr:hover td { background: rgba(88,166,255,.04); }

    /* ── Status row colours ──────────────────────────────────────────── */
    .row-new      td { background: rgba(63,185,80,.07);  }
    .row-modified td { background: rgba(210,153,34,.09); }
    .row-deleted  td { background: rgba(248,81,73,.08);
                       text-decoration: line-through; color: var(--muted); }

    /* ── Badges ──────────────────────────────────────────────────────── */
    .badge {
      display: inline-block; padding: 2px 8px; border-radius: 4px;
      font-size: 0.68rem; font-weight: 700; letter-spacing: .04em;
    }
    .badge-new      { background: rgba(63,185,80,.2);  color: var(--green);  border: 1px solid rgba(63,185,80,.45);  }
    .badge-modified { background: rgba(210,153,34,.2); color: var(--yellow); border: 1px solid rgba(210,153,34,.45); }
    .badge-deleted  { background: rgba(248,81,73,.2);  color: var(--red);    border: 1px solid rgba(248,81,73,.45);  }
    .badge-clean    { background: rgba(139,148,158,.15); color: var(--muted); border: 1px solid rgba(139,148,158,.3); }

    /* ── Misc ────────────────────────────────────────────────────────── */
    .mono  { font-family: 'SFMono-Regular', Consolas, monospace; font-size: 0.77rem; }
    .hash  { color: var(--muted); }
    .num   { text-align: right; }
    .meta  { font-size: 0.8rem; color: var(--muted); margin-bottom: 16px; }
    footer { margin-top: 40px; padding-top: 16px; border-top: 1px solid var(--border);
             color: var(--muted); font-size: 0.77rem; }
    """

    js = """
    const sortState = {};
    function sortTable(tableId, col) {
      const tbody = document.querySelector('#' + tableId + ' tbody');
      const rows  = Array.from(tbody.querySelectorAll('tr'));
      const asc   = !(sortState[tableId + col]);
      sortState[tableId + col] = asc;
      rows.sort((a, b) => {
        const av = a.cells[col]?.textContent.trim() || '';
        const bv = b.cells[col]?.textContent.trim() || '';
        const an = parseFloat(av.replace(/,/g, ''));
        const bn = parseFloat(bv.replace(/,/g, ''));
        if (!isNaN(an) && !isNaN(bn)) return asc ? an - bn : bn - an;
        return asc ? av.localeCompare(bv) : bv.localeCompare(av);
      });
      rows.forEach(r => tbody.appendChild(r));
    }
    """

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Cloud Forensics Dashboard — PRJN26-141</title>
  <style>{css}</style>
</head>
<body>

  <h1>Cloud Forensics Evidence Dashboard</h1>
  <div class="sub">
    Project PRJN26-141 &mdash; Energy Sector Breach Investigation
    &nbsp;|&nbsp; Generated: {scan_time}
  </div>

  {alert_banner}

  <div class="cards">
    <div class="card c-blue" ><div class="val">{total}</div><div class="label">Total Files</div></div>
    <div class="card c-red"  ><div class="val">{flagged}</div><div class="label">Flagged</div></div>
    <div class="card c-green"><div class="val">{len(new_files)}</div><div class="label">New</div></div>
    <div class="card c-yellow"><div class="val">{len(modified_files)}</div><div class="label">Modified</div></div>
    <div class="card c-red"  ><div class="val">{len(deleted_files)}</div><div class="label">Deleted</div></div>
    <div class="card c-green"><div class="val">{clean_count}</div><div class="label">Clean</div></div>
  </div>

  <div class="meta">Target directory: <span class="mono">{target_dir}</span></div>

  {flagged_section}

  <section>
    <h2>All Scanned Files</h2>
    <div class="table-wrap">
      <table id="mainTable">
        <thead>
          <tr>
            <th onclick="sortTable('mainTable',0)">Status</th>
            <th onclick="sortTable('mainTable',1)">Filename</th>
            <th onclick="sortTable('mainTable',2)">Type</th>
            <th onclick="sortTable('mainTable',3)">Size (B)</th>
            <th onclick="sortTable('mainTable',4)">Created</th>
            <th onclick="sortTable('mainTable',5)">Modified</th>
            <th onclick="sortTable('mainTable',6)">Accessed</th>
            <th>MD5 (partial)</th>
          </tr>
        </thead>
        <tbody>
          {main_rows}
        </tbody>
      </table>
    </div>
  </section>

  <footer>
    Cloud Forensics Automation &mdash; PRJN26-141 | Energy Sector Breach Analysis<br>
    Standard library only &mdash; no external dependencies | Python 3.10+
  </footer>

  <script>{js}</script>
</body>
</html>"""

    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(html)

    return out_path
