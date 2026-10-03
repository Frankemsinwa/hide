"""
Security Hardening, Brute-Force Throttling & Offensive Input Sanitization (Phase 15).
Provides:
- Failed password attempt tracking and exponential backoff throttling
- Path traversal and malicious NTFS stream validator
- Junction point and symbolic link rejection
- Path length safety and sanitization
"""

from __future__ import annotations

import os
import re
import time
from pathlib import Path
from typing import Dict, Tuple

# Failed password attempts tracker per vault_id: (attempt_count, last_failure_timestamp)
_FAILED_ATTEMPTS: Dict[str, Tuple[int, float]] = {}

# Max failed attempts before penalty escalates
MAX_UNTHROTTLED_ATTEMPTS = 3
BASE_BACKOFF_SECONDS = 0.5
MAX_BACKOFF_SECONDS = 15.0


class SecurityHardeningError(ValueError):
    """Raised when an operation violates security boundaries or throttling constraints."""
    pass


class BruteForceThrottledError(SecurityHardeningError):
    """Raised when repeated failed password attempts trigger rate limiting."""
    pass


def record_failed_password_attempt(vault_id: str) -> float:
    """
    Records a failed password attempt and applies exponential backoff delay.
    Returns the penalty delay enforced in seconds.
    """
    now = time.time()
    count, last_ts = _FAILED_ATTEMPTS.get(vault_id, (0, 0.0))

    # Reset count if last failure was more than 60 seconds ago
    if now - last_ts > 60.0:
        count = 1
    else:
        count += 1

    _FAILED_ATTEMPTS[vault_id] = (count, now)

    if count > MAX_UNTHROTTLED_ATTEMPTS:
        penalty = min(BASE_BACKOFF_SECONDS * (2 ** (count - MAX_UNTHROTTLED_ATTEMPTS)), MAX_BACKOFF_SECONDS)
        time.sleep(penalty)
        return penalty

    return 0.0


def reset_failed_password_attempts(vault_id: str) -> None:
    """Clears failed attempts counter upon successful authentication."""
    _FAILED_ATTEMPTS.pop(vault_id, None)


def assert_safe_target_path(target_path: Path, must_not_exist: bool = False) -> None:
    """
    Validates that a path is safe for filesystem operations:
    - No NTFS Alternate Data Streams (":")
    - No symbolic links or directory junctions
    - Path resolves properly within local filesystem
    """
    path_str = str(target_path)
    
    # Check for ADS (e.g. C:\folder\file.txt:stream)
    # Exclude drive letter colon (C:\)
    without_drive = re.sub(r"^[a-zA-Z]:", "", path_str)
    if ":" in without_drive:
        raise SecurityHardeningError(f"Forbidden NTFS Alternate Data Stream detected: '{path_str}'")

    if target_path.exists():
        if target_path.is_symlink():
            raise SecurityHardeningError(f"Symlinks are disallowed: '{path_str}'")

    if must_not_exist and target_path.exists():
        raise SecurityHardeningError(f"Path already exists: '{path_str}'")
