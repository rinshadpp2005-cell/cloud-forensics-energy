"""
hasher.py
---------
File hashing utilities using Python's built-in hashlib.
Computes MD5 and SHA-256 digests for forensic evidence integrity.

Reading in 64 KiB chunks avoids loading large files into memory at once.
"""

import hashlib
from pathlib import Path
from typing import Tuple

# Chunk size for streaming file reads (64 KiB)
_CHUNK_SIZE = 65_536


def compute_hashes(filepath: str | Path) -> Tuple[str, str]:
    """
    Compute MD5 and SHA-256 hashes for a file.

    Both hashes are computed in a single streaming pass for efficiency.

    Args:
        filepath: Absolute or relative path to the target file.

    Returns:
        Tuple of (md5_hex, sha256_hex). Returns ("ERROR", "ERROR") if the
        file cannot be read (permission denied, locked, etc.).
    """
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()

    try:
        with open(filepath, "rb") as fh:
            for chunk in iter(lambda: fh.read(_CHUNK_SIZE), b""):
                md5.update(chunk)
                sha256.update(chunk)
        return md5.hexdigest(), sha256.hexdigest()
    except (OSError, IOError):
        return "ERROR", "ERROR"
