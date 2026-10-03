"""
Path manipulation, containment verification, and path traversal security abstractions.
Protects against malicious relative paths, symlinks, junction points, and Windows reserved names.
"""

from __future__ import annotations

import os
import re
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Set

# Windows Reserved Device Names (cannot be used as filenames or directory components)
WINDOWS_RESERVED_NAMES: Set[str] = {
    "CON", "PRN", "AUX", "NUL",
    "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
    "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
}

# Regex to detect NTFS Alternate Data Stream notation (e.g. secret.txt:stream:$DATA)
ADS_REGEX = re.compile(r":[^\\/]+$")


class SecurityPathError(ValueError):
    """Raised when a path violates security constraints or attempts directory escape."""
    pass


def is_safe_file_name(name: str) -> bool:
    """
    Checks if a single filename component is safe on Windows and cross-platform filesystems.
    Rejects reserved DOS devices, characters like <>:\"/\\|?*, and trailing dots/spaces.
    """
    if not name or name in {".", ".."}:
        return False

    base_name = name.split(".")[0].upper()
    if base_name in WINDOWS_RESERVED_NAMES:
        return False

    # Illegal chars on Windows
    for ch in '<>:"/\\|?*':
        if ch in name:
            return False

    # Windows ignores or misbehaves on trailing spaces and dots
    if name.endswith(" ") or name.endswith("."):
        return False

    # Reject null bytes
    if "\0" in name:
        return False

    return True


def sanitize_vault_relative_path(path_str: str) -> str:
    """
    Sanitizes and canonicalizes an input path to be safely stored in the vault manifest.
    
    Guarantees:
    - POSIX style separators ('/')
    - No leading slashes or drive letters ('C:', '/')
    - Strict rejection of traversal tokens ('..')
    - Rejection of NTFS Alternate Data Streams
    - Rejection of reserved device names in path segments
    
    Returns clean canonical relative path (e.g. 'docs/images/logo.png').
    Raises SecurityPathError on malicious or invalid paths.
    """
    if "\0" in path_str:
        raise SecurityPathError("Path contains forbidden null byte.")

    # Remove Alternate Data Streams if present
    if ADS_REGEX.search(path_str):
        raise SecurityPathError(f"NTFS Alternate Data Stream detected in path: '{path_str}'")

    # Normalize backslashes to forward slashes
    normalized = path_str.replace("\\", "/").strip()

    # Reject drive letters or absolute paths
    if re.match(r"^[a-zA-Z]:", normalized) or normalized.startswith("/"):
        raise SecurityPathError(f"Absolute paths or drive letters are not allowed in vault: '{path_str}'")

    parts = [p for p in normalized.split("/") if p and p != "."]

    if not parts:
        raise SecurityPathError("Empty or invalid relative path.")

    # Validate each part
    for part in parts:
        if part == "..":
            raise SecurityPathError(f"Path traversal ('..') detected in: '{path_str}'")
        if not is_safe_file_name(part):
            raise SecurityPathError(f"Forbidden or reserved filename component '{part}' in: '{path_str}'")

    return "/".join(parts)


def validate_workspace_containment(workspace_root: Path, target_relative_path: str) -> Path:
    """
    Resolves target_relative_path inside workspace_root and verifies that the resulting
    path is strictly contained within workspace_root without escaping via symlinks or junctions.
    
    Guarantees:
    - Pure containment relative to root.
    - Inspects existing ancestors in chain for symlink or junction redirection.
    - Non-destructive (does not create directories during validation).
    
    Returns the validated absolute Path.
    Raises SecurityPathError if escape is attempted.
    """
    clean_rel = sanitize_vault_relative_path(target_relative_path)
    root_resolved = workspace_root.resolve()
    
    # Construct candidate destination
    candidate = root_resolved.joinpath(*clean_rel.split("/"))
    
    try:
        candidate.relative_to(root_resolved)
    except ValueError:
        raise SecurityPathError(
            f"Directory traversal detected: '{clean_rel}' resolves outside workspace root '{root_resolved}'"
        )

    # Walk up the chain of existing elements to ensure no symlink redirects outside root
    curr = candidate
    while curr != root_resolved and curr != curr.parent:
        if curr.exists():
            if curr.is_symlink():
                raise SecurityPathError(f"Symlinks are disallowed inside vault workspaces: '{curr}'")
            resolved_curr = curr.resolve()
            try:
                resolved_curr.relative_to(root_resolved)
            except ValueError:
                raise SecurityPathError(
                    f"Symlink / junction escape detected at: '{curr}' -> '{resolved_curr}'"
                )
        curr = curr.parent

    return candidate


def ensure_long_path_support(path: Path) -> str:
    """
    Prefixes path with \\?\\ for Windows extended-length paths if needed (>250 chars).
    """
    abs_str = str(path.resolve())
    if os.name == "nt" and len(abs_str) > 240 and not abs_str.startswith("\\\\?\\"):
        return f"\\\\?\\{abs_str}"
    return abs_str
