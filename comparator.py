"""
comparator.py
-------------
Baseline management and tamper-detection logic.

A baseline is a JSON snapshot of every file's hashes + timestamps taken at a
known-good point in time.  Subsequent scans are diffed against the baseline
to surface NEW, MODIFIED, and DELETED files.
"""

import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple

BASELINES_DIR = "baselines"

logger = logging.getLogger("forensic_tool")


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _baseline_path(target_dir: str | Path) -> str:
    """
    Derive a stable filename for the baseline JSON from the target directory.

    We replace path separators and colons so the result is a valid filename
    on both Windows and Unix.
    """
    resolved = str(Path(target_dir).resolve())
    sanitized = resolved.replace("\\", "_").replace("/", "_").replace(":", "").strip("_")
    return os.path.join(BASELINES_DIR, f"baseline_{sanitized}.json")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def save_baseline(
    file_records: List[Dict[str, Any]],
    target_dir: str | Path,
    logger=None,
) -> str:
    """
    Persist a baseline JSON from the given scan records.

    The baseline stores only the fields needed for comparison: hashes, size,
    and last-modified timestamp.

    Args:
        file_records: List of metadata dicts as returned by scanner.scan_directory().
        target_dir:   The directory that was scanned (stored in the baseline for audit).
        logger:       Optional logger; falls back to module logger.

    Returns:
        Path to the written baseline file.
    """
    log = logger or logging.getLogger("forensic_tool")
    os.makedirs(BASELINES_DIR, exist_ok=True)

    path = _baseline_path(target_dir)
    baseline = {
        "created":          datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "target_directory": str(Path(target_dir).resolve()),
        "file_count":       len(file_records),
        "files": {
            record["filepath"]: {
                "md5":        record["md5"],
                "sha256":     record["sha256"],
                "size_bytes": record["size_bytes"],
                "modified":   record["modified"],
            }
            for record in file_records
        },
    }

    with open(path, "w", encoding="utf-8") as fh:
        json.dump(baseline, fh, indent=2)

    log.info(f"Baseline saved → {path}  ({len(file_records)} files indexed)")
    return path


def load_baseline(
    target_dir: str | Path,
    logger=None,
) -> Optional[Dict[str, Any]]:
    """
    Load an existing baseline for the given directory.

    Args:
        target_dir: Directory whose baseline should be loaded.
        logger:     Optional logger.

    Returns:
        Parsed baseline dict, or None if no baseline exists.
    """
    log = logger or logging.getLogger("forensic_tool")
    path = _baseline_path(target_dir)

    if not os.path.exists(path):
        log.warning(f"No baseline found at: {path}")
        return None

    with open(path, "r", encoding="utf-8") as fh:
        baseline = json.load(fh)

    log.info(
        f"Baseline loaded ← {path}  "
        f"(created {baseline.get('created', 'unknown')}, "
        f"{baseline.get('file_count', '?')} files)"
    )
    return baseline


def compare_with_baseline(
    current_records: List[Dict[str, Any]],
    baseline: Optional[Dict[str, Any]],
    logger=None,
) -> Tuple[List[Dict], List[Dict], List[Dict]]:
    """
    Diff current scan records against the baseline.

    Comparison logic:
      - NEW      : filepath present in scan but absent from baseline.
      - MODIFIED : filepath in both, but SHA-256 or MD5 differs.
      - DELETED  : filepath in baseline but absent from current scan.
      - UNCHANGED: filepath in both with identical hashes.

    Each record is annotated with a 'status' key in-place.

    Args:
        current_records: Scan results from scanner.scan_directory().
        baseline:        Loaded baseline dict (or None → no comparison).
        logger:          Optional logger.

    Returns:
        Tuple of (new_files, modified_files, deleted_files) — each a list of
        annotated record dicts.
    """
    log = logger or logging.getLogger("forensic_tool")

    if baseline is None:
        # No baseline available — mark everything as NEW
        for r in current_records:
            r["status"] = "NEW"
        return list(current_records), [], []

    baseline_files: Dict[str, Any] = baseline.get("files", {})
    current_map: Dict[str, Dict] = {r["filepath"]: r for r in current_records}

    new_files:      List[Dict] = []
    modified_files: List[Dict] = []
    deleted_files:  List[Dict] = []

    # Pass 1 — check every current file against the baseline
    for filepath, record in current_map.items():
        if filepath not in baseline_files:
            record["status"] = "NEW"
            new_files.append(record)
            log.debug(f"[NEW]      {filepath}")
        else:
            bl = baseline_files[filepath]
            if record["sha256"] != bl["sha256"] or record["md5"] != bl["md5"]:
                record["status"] = "MODIFIED"
                # Preserve baseline hashes for diff display
                record["baseline_md5"]    = bl["md5"]
                record["baseline_sha256"] = bl["sha256"]
                modified_files.append(record)
                log.debug(f"[MODIFIED] {filepath}")
            else:
                record["status"] = "UNCHANGED"

    # Pass 2 — find files that existed in the baseline but are now gone
    for filepath, bl in baseline_files.items():
        if filepath not in current_map:
            deleted_record: Dict[str, Any] = {
                "filename":   Path(filepath).name,
                "filepath":   filepath,
                "extension":  Path(filepath).suffix.lower() or "(none)",
                "size_bytes": bl["size_bytes"],
                "created":    "N/A (deleted)",
                "modified":   bl["modified"],
                "accessed":   "N/A (deleted)",
                "md5":        bl["md5"],
                "sha256":     bl["sha256"],
                "status":     "DELETED",
            }
            deleted_files.append(deleted_record)
            log.debug(f"[DELETED]  {filepath}")

    log.info(
        f"Comparison complete — "
        f"{len(new_files)} new | "
        f"{len(modified_files)} modified | "
        f"{len(deleted_files)} deleted"
    )
    return new_files, modified_files, deleted_files
