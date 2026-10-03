"""
Transactional Crash Recovery & Health Audit Subsystem (Phase 11).
Inspects state.lock, validates process vitality, and recovers interrupted operations
without data loss.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Dict, Optional, Tuple

from hide.core.metadata import (
    META_FILENAME,
    read_vault_metadata,
)
from hide.core.models import TransactionState, VaultLockState
from hide.core.vault import (
    STATE_LOCK_FILENAME,
    JOURNAL_FILENAME,
    remove_vault_lock,
)


def is_pid_running(pid: int) -> bool:
    """Checks whether a process with given PID is currently active."""
    if pid <= 0:
        return False
    if os.name == "nt":
        # Windows process check using OpenProcess or tasklist
        import ctypes
        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if handle:
            kernel32.CloseHandle(handle)
            return True
        return False
    else:
        try:
            os.kill(pid, 0)
            return True
        except OSError:
            return False


def get_vault_operational_status(vault_dir: Path) -> Tuple[TransactionState, Optional[VaultLockState]]:
    """
    Evaluates the real-time operational state of a vault container.
    Detects stale locks where the recorded process died.
    """
    vault_dir = vault_dir.resolve()
    lock_file = vault_dir / STATE_LOCK_FILENAME

    if not lock_file.is_file():
        return TransactionState.CLOSED, None

    try:
        with open(lock_file, "r", encoding="utf-8") as f:
            data = json.load(f)
            lock_state = VaultLockState.from_dict(data)
    except Exception:
        return TransactionState.RECOVERY_REQUIRED, None

    # Check if the process that held the lock has died
    if lock_state.state in (TransactionState.OPEN, TransactionState.ENCRYPTING, TransactionState.CLOSING):
        if not is_pid_running(lock_state.pid):
            # Process crashed!
            return TransactionState.RECOVERY_REQUIRED, lock_state

    return lock_state.state, lock_state


def recover_interrupted_vault(vault_dir: Path) -> str:
    """
    Attempts safe recovery of an interrupted vault transaction.
    Guarantees:
    - If workspace still exists with plaintext files, it is kept intact for user safety.
    - If a stale lock exists with no running process, it resets the lock safely.
    """
    vault_dir = vault_dir.resolve()
    status, lock_state = get_vault_operational_status(vault_dir)

    if status == TransactionState.CLOSED:
        return "Vault is already in a clean CLOSED state. No recovery needed."

    if lock_state and lock_state.workspace_path:
        ws_path = Path(lock_state.workspace_path)
        if ws_path.is_dir() and any(ws_path.iterdir()):
            # Safe recovery: leave workspace available for the user
            remove_vault_lock(vault_dir)
            return f"Recovery complete. Active workspace preserved at '{ws_path}'. Lock reset to CLOSED."

    # If no active workspace or empty, reset stale lock
    remove_vault_lock(vault_dir)
    return "Recovery complete. Stale transaction lock cleared. State reset to CLOSED."
