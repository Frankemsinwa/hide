"""
Local Vault Registry Management (Phase 6 & 8).
Maintains ~/.hide/registry.json for tracking registered vaults across the system.
"""

from __future__ import annotations

import json
import os
import tempfile
import time
from pathlib import Path
from typing import Dict, List, Optional

from hide.core.models import TransactionState, VaultSummary
from hide.core.metadata import read_vault_metadata, META_FILENAME


def get_default_hide_home() -> Path:
    """Returns ~/.hide directory path."""
    home = Path.home() / ".hide"
    home.mkdir(parents=True, exist_ok=True)
    return home


def get_default_vaults_dir() -> Path:
    """Returns ~/.hide/vaults directory path."""
    vaults_dir = get_default_hide_home() / "vaults"
    vaults_dir.mkdir(parents=True, exist_ok=True)
    return vaults_dir


def get_registry_path() -> Path:
    """Returns ~/.hide/registry.json path."""
    return get_default_hide_home() / "registry.json"


class VaultRegistry:
    """
    Thread-safe & atomic local vault registry.
    Maps vault_id -> vault details.
    """

    def __init__(self, registry_file: Optional[Path] = None):
        self.registry_file = registry_file or get_registry_path()

    def _read_data(self) -> Dict[str, dict]:
        if not self.registry_file.is_file():
            return {}
        try:
            with open(self.registry_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}

    def _write_data_atomic(self, data: Dict[str, dict]) -> None:
        self.registry_file.parent.mkdir(parents=True, exist_ok=True)
        raw_bytes = json.dumps(data, indent=2).encode("utf-8")
        
        tmp_fd, tmp_file = tempfile.mkstemp(
            prefix="reg_", suffix=".tmp", dir=str(self.registry_file.parent)
        )
        try:
            with os.fdopen(tmp_fd, "wb") as f:
                f.write(raw_bytes)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_file, self.registry_file)
        except Exception:
            if os.path.exists(tmp_file):
                try:
                    os.remove(tmp_file)
                except OSError:
                    pass
            raise

    def register_vault(self, vault_path: Path, vault_name: Optional[str] = None) -> VaultSummary:
        """
        Registers a vault directory into the global registry.
        """
        vault_path = vault_path.resolve()
        meta_file = vault_path / META_FILENAME
        meta = read_vault_metadata(meta_file)

        name = vault_name or meta.vault_name
        data = self._read_data()
        
        # Calculate size on disk
        size_bytes = 0
        for root, _, files in os.walk(vault_path):
            for file in files:
                try:
                    size_bytes += os.path.getsize(os.path.join(root, file))
                except OSError:
                    pass

        entry = {
            "vault_id": meta.vault_id,
            "name": name,
            "path": str(vault_path),
            "created_at_utc": meta.created_at_utc,
            "last_seen_utc": time.time(),
        }
        data[meta.vault_id] = entry
        self._write_data_atomic(data)

        return VaultSummary(
            vault_id=meta.vault_id,
            name=name,
            path=str(vault_path),
            status=TransactionState.CLOSED,
            size_on_disk_bytes=size_bytes,
            created_at_utc=meta.created_at_utc,
        )

    def unregister_vault(self, vault_id: str) -> bool:
        """Removes a vault from the registry."""
        data = self._read_data()
        if vault_id in data:
            del data[vault_id]
            self._write_data_atomic(data)
            return True
        return False

    def list_vaults(self) -> List[VaultSummary]:
        """
        Returns a list of all registered vaults and their current on-disk states.
        """
        data = self._read_data()
        summaries: List[VaultSummary] = []

        for vault_id, entry in data.items():
            vault_path = Path(entry["path"])
            status = TransactionState.CLOSED
            size_bytes = 0

            if not vault_path.exists():
                status = TransactionState.RECOVERY_REQUIRED
            else:
                meta_file = vault_path / META_FILENAME
                if not meta_file.is_file():
                    status = TransactionState.RECOVERY_REQUIRED
                else:
                    lock_file = vault_path / "state.lock"
                    if lock_file.is_file():
                        try:
                            with open(lock_file, "r", encoding="utf-8") as lf:
                                lock_data = json.load(lf)
                                status = TransactionState(lock_data.get("state", "OPEN"))
                        except Exception:
                            status = TransactionState.OPEN
                    
                    # Calculate disk usage
                    for root, _, files in os.walk(vault_path):
                        for file in files:
                            try:
                                size_bytes += os.path.getsize(os.path.join(root, file))
                            except OSError:
                                pass

            summaries.append(
                VaultSummary(
                    vault_id=vault_id,
                    name=entry.get("name", "Unnamed"),
                    path=entry["path"],
                    status=status,
                    size_on_disk_bytes=size_bytes,
                    created_at_utc=entry.get("created_at_utc", 0.0),
                )
            )

        return summaries

    def find_vault(self, identifier: str) -> Optional[VaultSummary]:
        """
        Finds a vault by 1-based index (string '1', '2'), partial or exact name, or vault_id.
        """
        vaults = self.list_vaults()
        if not vaults:
            return None

        # Check 1-based index
        if identifier.isdigit():
            idx = int(identifier) - 1
            if 0 <= idx < len(vaults):
                return vaults[idx]

        # Check exact vault_id or name
        for v in vaults:
            if v.vault_id == identifier or v.name.lower() == identifier.lower():
                return v

        # Check partial match on name or ID prefix
        for v in vaults:
            if identifier.lower() in v.name.lower() or v.vault_id.startswith(identifier):
                return v

        return None
