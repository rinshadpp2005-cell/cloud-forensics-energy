"""
logger_config.py
----------------
Centralized logging configuration for the Cloud Forensics tool.
Outputs to both forensic_log.txt (DEBUG+) and the console (INFO+).
"""

import logging
import os


def setup_logger(log_file: str = "forensic_log.txt") -> logging.Logger:
    """
    Configure and return the application-wide logger.

    Args:
        log_file: Path to the log file. Defaults to 'forensic_log.txt'
                  in the current working directory.

    Returns:
        Configured Logger instance named 'forensic_tool'.
    """
    logger = logging.getLogger("forensic_tool")

    # Prevent duplicate handlers if called multiple times
    if logger.handlers:
        return logger

    logger.setLevel(logging.DEBUG)

    fmt = logging.Formatter(
        fmt="%(asctime)s [%(levelname)-8s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # --- File handler (DEBUG level — captures everything) ---
    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)

    # --- Console handler (INFO level — surface-level progress only) ---
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    ch.setFormatter(fmt)

    logger.addHandler(fh)
    logger.addHandler(ch)

    return logger
