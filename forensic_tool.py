#!/usr/bin/env python3
"""
forensic_tool.py
----------------
Cloud Forensics File Evidence Collector — Energy Sector
Project: PRJN26-141

Entry-point CLI with three sub-commands:

  scan      Scan a directory, compare against baseline (if one exists),
            and produce CSV + HTML evidence reports.

  baseline  Create or overwrite the hash baseline for a directory so
            future scans have a known-good reference point.

  compare   Diff current directory state against the baseline and print
            a human-readable change summary to stdout.  Optionally also
            generates CSV + HTML reports (--report flag).

Usage examples:
  python forensic_tool.py scan     --path sample_energy_data/
  python forensic_tool.py baseline --path sample_energy_data/
  python forensic_tool.py compare  --path sample_energy_data/ --report
"""

import argparse
import os
import sys
from datetime import datetime

from logger_config import setup_logger
from scanner import scan_directory
from comparator import save_baseline, load_baseline, compare_with_baseline
from report_generator import generate_csv_report, generate_html_report


# ─────────────────────────────────────────────────────────────────────────────
# Sub-command handlers
# ─────────────────────────────────────────────────────────────────────────────

def cmd_baseline(args, logger) -> None:
    """Create or update a baseline for the target directory."""
    logger.info(f"[BASELINE] Target: {args.path}")

    records      = scan_directory(args.path, logger)
    baseline_path = save_baseline(records, args.path, logger)

    print(f"\n[+] Baseline created successfully!")
    print(f"    Files indexed : {len(records)}")
    print(f"    Baseline file : {baseline_path}")
    print(f"    Timestamp     : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"    Log file      : forensic_log.txt")


def cmd_scan(args, logger) -> None:
    """Scan directory and generate CSV + HTML evidence reports."""
    logger.info(f"[SCAN] Target: {args.path}")

    records  = scan_directory(args.path, logger)
    baseline = load_baseline(args.path, logger)

    if baseline:
        new_files, modified, deleted = compare_with_baseline(records, baseline, logger)
    else:
        logger.warning("No baseline found — all files will be marked NEW in the report.")
        new_files, modified, deleted = [], [], []
        for rec in records:
            rec["status"] = "NEW"
        new_files = list(records)

    output_dir = args.output or "."
    os.makedirs(output_dir, exist_ok=True)

    csv_path  = generate_csv_report(records, new_files, modified, deleted, output_dir)
    html_path = generate_html_report(records, new_files, modified, deleted, args.path, output_dir)

    flagged = len(new_files) + len(modified) + len(deleted)

    print(f"\n[+] Scan complete!")
    print(f"    Total files   : {len(records)}")
    print(f"    Flagged files : {flagged}")
    print(f"      NEW         : {len(new_files)}")
    print(f"      MODIFIED    : {len(modified)}")
    print(f"      DELETED     : {len(deleted)}")
    print(f"    CSV Report    : {csv_path}")
    print(f"    HTML Dashboard: {html_path}")
    print(f"    Log file      : forensic_log.txt")

    if flagged > 0:
        logger.warning(f"ALERT: {flagged} suspicious file(s) detected in '{args.path}'")
        print(f"\n[!] WARNING: {flagged} suspicious file(s) detected. Review the HTML dashboard.")
    else:
        print("\n[OK] No tampered files detected. All hashes match the baseline.")


def cmd_compare(args, logger) -> None:
    """Compare current directory state against the saved baseline."""
    logger.info(f"[COMPARE] Target: {args.path}")

    baseline = load_baseline(args.path, logger)
    if not baseline:
        print(f"\n[!] No baseline found for: {args.path}")
        print(f"    Run first: python forensic_tool.py baseline --path \"{args.path}\"")
        sys.exit(1)

    records = scan_directory(args.path, logger)
    new_files, modified, deleted = compare_with_baseline(records, baseline, logger)
    flagged = len(new_files) + len(modified) + len(deleted)

    print(f"\n[+] Comparison complete!")
    print(f"    Baseline from : {baseline.get('created', 'unknown')}")
    print(f"    Total files   : {len(records)}")
    print(f"    Flagged       : {flagged}")

    if new_files:
        print(f"\n  [NEW FILES — {len(new_files)}]")
        for rec in new_files:
            print(f"    + {rec['filepath']}")

    if modified:
        print(f"\n  [MODIFIED FILES — {len(modified)}]")
        for rec in modified:
            print(f"    ~ {rec['filepath']}")
            print(f"      Current SHA256  : {rec['sha256']}")
            print(f"      Baseline SHA256 : {rec.get('baseline_sha256', 'N/A')}")

    if deleted:
        print(f"\n  [DELETED FILES — {len(deleted)}]")
        for rec in deleted:
            print(f"    - {rec['filepath']}")

    if flagged == 0:
        print("\n  [OK] All files match baseline. No tampering detected.")
    else:
        logger.warning(f"ALERT: {flagged} suspicious change(s) detected in '{args.path}'")

    if args.report:
        output_dir = args.output or "."
        os.makedirs(output_dir, exist_ok=True)
        csv_path  = generate_csv_report(records, new_files, modified, deleted, output_dir)
        html_path = generate_html_report(records, new_files, modified, deleted, args.path, output_dir)
        print(f"\n    CSV Report    : {csv_path}")
        print(f"    HTML Dashboard: {html_path}")


# ─────────────────────────────────────────────────────────────────────────────
# CLI definition
# ─────────────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="forensic_tool",
        description="Cloud Forensics File Evidence Collector — Energy Sector (PRJN26-141)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Commands:
  scan      Scan directory, compare against baseline, generate CSV + HTML reports.
  baseline  Create or update a hash baseline for a directory.
  compare   Compare current state against baseline; print changes to console.

Examples:
  python forensic_tool.py scan     --path sample_energy_data/
  python forensic_tool.py baseline --path sample_energy_data/
  python forensic_tool.py compare  --path sample_energy_data/ --report
  python forensic_tool.py scan     --path sample_energy_data/ --output reports/
        """,
    )

    sub = parser.add_subparsers(dest="command", required=True)

    # ── scan ─────────────────────────────────────────────────────────────────
    p_scan = sub.add_parser("scan", help="Scan directory and generate evidence reports")
    p_scan.add_argument("--path",   required=True, help="Target directory to scan")
    p_scan.add_argument("--output", default=".",   help="Output folder for reports (default: .)")

    # ── baseline ──────────────────────────────────────────────────────────────
    p_bl = sub.add_parser("baseline", help="Create or update a file hash baseline")
    p_bl.add_argument("--path", required=True, help="Target directory to baseline")

    # ── compare ───────────────────────────────────────────────────────────────
    p_cmp = sub.add_parser("compare", help="Compare directory against saved baseline")
    p_cmp.add_argument("--path",   required=True,      help="Target directory to compare")
    p_cmp.add_argument("--report", action="store_true", help="Also generate CSV + HTML reports")
    p_cmp.add_argument("--output", default=".",         help="Output folder for reports (default: .)")

    return parser


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = build_parser()
    args   = parser.parse_args()
    logger = setup_logger()

    logger.info(f"=== Forensic Tool Started  |  Command: {args.command} ===")

    try:
        if args.command == "scan":
            cmd_scan(args, logger)
        elif args.command == "baseline":
            cmd_baseline(args, logger)
        elif args.command == "compare":
            cmd_compare(args, logger)
    except KeyboardInterrupt:
        logger.info("Interrupted by user.")
        sys.exit(0)
    except Exception as exc:
        logger.error(f"Fatal error: {exc}", exc_info=True)
        print(f"\n[ERROR] {exc}")
        sys.exit(1)
    finally:
        logger.info(f"=== Forensic Tool Finished |  Command: {args.command} ===")


if __name__ == "__main__":
    main()
