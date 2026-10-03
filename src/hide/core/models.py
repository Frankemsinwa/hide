"""
Core domain models and state representations for Hide vaults.
Follows zero-knowledge security principles and strict schema validation.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Dict, List, Optional
import time
import uuid


class TransactionState(str, Enum):
    """
    Lifecycle transaction states for crash recovery and concurrency control.
    """
    CLOSED = "CLOSED"
    AUTHENTICATING = "AUTHENTICATING"
    DECRYPTING = "DECRYPTING"
    OPEN = "OPEN"
    CLOSING = "CLOSING"
    ENCRYPTING = "ENCRYPTING"
    SYNC_VERIFIED = "SYNC_VERIFIED"
    WIPING_WORKSPACE = "WIPING_WORKSPACE"
    PANIC_LOCKED = "PANIC_LOCKED"
    RECOVERY_REQUIRED = "RECOVERY_REQUIRED"


@dataclass
class KdfParameters:
    """
    Argon2id Key Derivation Function parameters.
    """
    algorithm: str = "argon2id"
    salt_b64: str = ""
    memory_cost_kib: int = 65536     # 64 MiB
    time_cost: int = 3               # 3 iterations
    parallelism: int = 4             # 4 threads
    derived_key_bytes: int = 32      # 256 bits

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> KdfParameters:
        return cls(**data)


@dataclass
class AuthCheckToken:
    """
    Fast password-verification token encrypted under the derived key.
    Enables instant rejection of bad passwords (~200ms) before processing multi-GB data.
    """
    nonce_b64: str
    ciphertext_b64: str
    tag_b64: str

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> AuthCheckToken:
        return cls(**data)


@dataclass
class VaultMetadata:
    """
    Unencrypted public header stored in `vault.meta`.
    Contains strictly no plaintext filenames, sizes, or file counts.
    """
    format_version: int
    vault_id: str
    vault_name: str
    created_at_utc: float
    cipher: str
    kdf: KdfParameters
    auth_check: AuthCheckToken

    def to_dict(self) -> dict:
        return {
            "format_version": self.format_version,
            "vault_id": self.vault_id,
            "vault_name": self.vault_name,
            "created_at_utc": self.created_at_utc,
            "cipher": self.cipher,
            "kdf": self.kdf.to_dict(),
            "auth_check": self.auth_check.to_dict(),
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_dict(cls, data: dict) -> VaultMetadata:
        return cls(
            format_version=data["format_version"],
            vault_id=data["vault_id"],
            vault_name=data["vault_name"],
            created_at_utc=data["created_at_utc"],
            cipher=data.get("cipher", "aes-256-gcm"),
            kdf=KdfParameters.from_dict(data["kdf"]),
            auth_check=AuthCheckToken.from_dict(data["auth_check"]),
        )

    @classmethod
    def from_json(cls, json_str: str) -> VaultMetadata:
        return cls.from_dict(json.loads(json_str))


@dataclass
class ManifestEntry:
    """
    Represents a single file or directory inside the encrypted vault.
    Stored inside the encrypted `manifest.enc`.
    """
    rel_path: str               # Canonical relative path inside vault (posix style, e.g. "docs/plan.md")
    is_dir: bool = False
    size_bytes: int = 0
    plaintext_sha256: str = ""  # Hex digest of plaintext for round-trip verification
    object_id: str = ""         # UUID referencing `objects/xx/yy...` on disk
    created_at: float = 0.0
    modified_at: float = 0.0
    file_mode: int = 0          # Attributes/permissions

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> ManifestEntry:
        return cls(**data)


@dataclass
class VaultManifest:
    """
    The full decrypted catalog of a vault.
    Serialized and encrypted with AES-256-GCM into `manifest.enc`.
    """
    vault_id: str
    version: int
    updated_at: float
    entries: Dict[str, ManifestEntry] = field(default_factory=dict)

    def add_entry(self, entry: ManifestEntry) -> None:
        self.entries[entry.rel_path] = entry

    def remove_entry(self, rel_path: str) -> Optional[ManifestEntry]:
        return self.entries.pop(rel_path, None)

    def get_total_size(self) -> int:
        return sum(entry.size_bytes for entry in self.entries.values() if not entry.is_dir)

    def get_file_count(self) -> int:
        return sum(1 for entry in self.entries.values() if not entry.is_dir)

    def to_dict(self) -> dict:
        return {
            "vault_id": self.vault_id,
            "version": self.version,
            "updated_at": self.updated_at,
            "entries": {k: v.to_dict() for k, v in self.entries.items()},
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    @classmethod
    def from_dict(cls, data: dict) -> VaultManifest:
        entries = {k: ManifestEntry.from_dict(v) for k, v in data.get("entries", {}).items()}
        return cls(
            vault_id=data["vault_id"],
            version=data["version"],
            updated_at=data["updated_at"],
            entries=entries,
        )

    @classmethod
    def from_json(cls, json_str: str) -> VaultManifest:
        return cls.from_dict(json.loads(json_str))


@dataclass
class EncryptedObjectMeta:
    """
    Represents an encrypted payload object stored in `objects/ab/cdef...enc`.
    """
    object_id: str
    chunk_count: int
    total_cipher_bytes: int
    nonce_b64: str
    tag_b64: str

    @property
    def disk_subpath(self) -> str:
        """
        Shards objects into 2-character prefixes to prevent filesystem slowdowns.
        e.g., 'a1b2c3d4' -> 'a1/b2c3d4.enc'
        """
        clean_id = self.object_id.replace("-", "")
        prefix = clean_id[:2]
        rest = clean_id[2:]
        return f"{prefix}/{rest}.enc"


@dataclass
class VaultLockState:
    """
    Lockfile state recorded in `state.lock`.
    Enforces concurrency limits and tracks active processes.
    """
    vault_id: str
    state: TransactionState
    pid: int
    acquired_at: float
    workspace_path: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "vault_id": self.vault_id,
            "state": self.state.value,
            "pid": self.pid,
            "acquired_at": self.acquired_at,
            "workspace_path": self.workspace_path,
        }

    @classmethod
    def from_dict(cls, data: dict) -> VaultLockState:
        return cls(
            vault_id=data["vault_id"],
            state=TransactionState(data["state"]),
            pid=data["pid"],
            acquired_at=data["acquired_at"],
            workspace_path=data.get("workspace_path"),
        )


@dataclass
class VaultSummary:
    """
    Lightweight representation of a registered vault for `hide list`.
    """
    vault_id: str
    name: str
    path: str
    status: TransactionState
    size_on_disk_bytes: int
    created_at_utc: float
    file_count: Optional[int] = None
