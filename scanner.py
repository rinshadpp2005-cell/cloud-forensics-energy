"""
scanner.py
----------
Recursive directory scanner for forensic evidence collection.

For every regular file under the target directory, collects:
  - Filename, full path, extension
  - Size in bytes
  - Timestamps: created, modified, accessed
  - MD5 and SHA-256 hashes
"""

import os
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any

from hasher import compute_hashes

logger = logging.getLogger("forensic_tool")

# Directories to skip during traversal (OS artifacts, hidden folders)
_SKIP_DIRS = {".git", "__pycache__", ".DS_Store", "Thumbs.db"}


def _fmt_ts(epoch: float) -> str:
    """Convert a POSIX timestamp to a human-readable string."""
    return datetime.fromtimestamp(epoch).strftime("%Y-%m-%d %H:%M:%S")


def get_file_metadata(filepath: str | Path) -> Dict[str, Any]:
    """
    Collect all forensic metadata for a single file.

    Args:
        filepath: Path to the file.

    Returns:
        Dictionary with keys: filename, filepath, extension, size_bytes,
        created, modified, accessed, md5, sha256.
    """
    path = Path(filepath).resolve()
    stat = path.stat()
    md5, sha256 = compute_hashes(path)

    return {
        "filename":   path.name,
        "filepath":   str(path),
        "extension":  path.suffix.lower() if path.suffix else "(none)",
        "size_bytes": stat.st_size,
        "created":    _fmt_ts(stat.st_ctime),   # creation time (Windows) / inode change (Unix)
        "modified":   _fmt_ts(stat.st_mtime),
        "accessed":   _fmt_ts(stat.st_atime),
        "md5":        md5,
        "sha256":     sha256,
    }


def scan_directory(directory: str | Path, logger=None) -> List[Dict[str, Any]]:
    """
    Recursively scan a directory and return metadata for every file found.

    Hidden directories and OS artefacts listed in _SKIP_DIRS are skipped.
    Files that cannot be read (locked, permission-denied) are logged as
    warnings and omitted from the results.

    Args:
        directory: Root directory to scan.
        logger:    Optional logger instance; falls back to module logger.

    Returns:
        List of file metadata dictionaries, one per file.

    Raises:
        FileNotFoundError: If directory does not exist.
        NotADirectoryError: If path exists but is not a directory.
    """
    log = logger or logging.getLogger("forensic_tool")
    directory = Path(directory)

    if not directory.exists():
        log.error(f"Directory does not exist: {directory}")
        raise FileNotFoundError(f"Directory not found: {directory}")

    if not directory.is_dir():
        log.error(f"Path is not a directory: {directory}")
        raise NotADirectoryError(f"Not a directory: {directory}")

    log.info(f"Scanning directory: {directory}")
    results: List[Dict[str, Any]] = []

    for root, dirs, files in os.walk(directory):
        # Prune unwanted subdirectories in-place so os.walk skips them
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS and not d.startswith(".")]

        for filename in sorted(files):
            filepath = os.path.join(root, filename)
            try:
                metadata = get_file_metadata(filepath)
                results.append(metadata)
                log.debug(f"Scanned [{metadata['size_bytes']:>10} B] {filepath}")
            except Exception as exc:
                log.warning(f"Could not scan '{filepath}': {exc}")

    log.info(f"Scan complete — {len(results)} file(s) collected from '{directory}'")
    return results
