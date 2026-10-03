"""
Temporary Workspace Management, Decryption & Staging Engine (Phase 9 & 10).
Handles:
- `hide open`: Decrypts manifest, stages files into isolated workspace, sets permissions.
- Snapshot state: tracks baseline file sizes, modification times, and SHA-256 digests.
- Differential change detector: identifies new, modified, and deleted files.
- Differential re-encryption: only re-encrypts modified/new objects.
- Workspace wipe: shredding all decrypted files and directories on unmount.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import time
import uuid
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Callable, Dict, List, Optional, Set, Tuple

from hide.core.crypto import (
    AES_KEY_SIZE_BYTES,
    decrypt_stream,
    encrypt_stream,
    DecryptionIntegrityError,
)
from hide.core.kdf import EphemeralKey
from hide.core.manifest import (
    MANIFEST_FILENAME,
    read_encrypted_manifest,
    write_encrypted_manifest,
)
from hide.core.metadata import (
    META_FILENAME,
    read_vault_metadata,
    unlock_vault_metadata,
)
from hide.core.models import (
    ManifestEntry,
    TransactionState,
    VaultLockState,
    VaultManifest,
)
from hide.core.paths import (
    sanitize_vault_relative_path,
    validate_workspace_containment,
    ensure_long_path_support,
)
from hide.core.registry import get_default_hide_home
from hide.core.vault import (
    OBJECTS_DIRNAME,
    STATE_LOCK_FILENAME,
    JOURNAL_FILENAME,
    get_object_rel_path,
    record_vault_lock,
    remove_vault_lock,
    secure_wipe_directory,
    secure_wipe_file,
    VaultOperationError,
)


def get_default_workspaces_dir() -> Path:
    """Returns ~/.hide/workspaces directory."""
    ws = get_default_hide_home() / "workspaces"
    ws.mkdir(parents=True, exist_ok=True)
    return ws


@dataclass
class FileSnapshot:
    """Records file state when workspace is first opened."""
    rel_path: str
    is_dir: bool
    size_bytes: int
    modified_at: float
    sha256_hash: str = ""

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> FileSnapshot:
        return cls(**d)


@dataclass
class WorkspaceSnapshot:
    """Saved in workspace as .hide_snapshot.json to detect changes on close."""
    vault_id: str
    vault_dir: str
    opened_at: float
    files: Dict[str, FileSnapshot] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "vault_id": self.vault_id,
            "vault_dir": self.vault_dir,
            "opened_at": self.opened_at,
            "files": {k: v.to_dict() for k, v in self.files.items()},
        }

    def save_to_file(self, snapshot_file: Path) -> None:
        with open(snapshot_file, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2)

    @classmethod
    def load_from_file(cls, snapshot_file: Path) -> WorkspaceSnapshot:
        with open(snapshot_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        files = {k: FileSnapshot.from_dict(v) for k, v in data.get("files", {}).items()}
        return cls(
            vault_id=data["vault_id"],
            vault_dir=data["vault_dir"],
            opened_at=data["opened_at"],
            files=files,
        )


SNAPSHOT_FILENAME = ".hide_snapshot.json"


def compute_file_sha256(file_path: Path) -> str:
    """Computes SHA-256 digest of a local plaintext file."""
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


def open_vault_workspace(
    vault_dir: Path,
    password: str,
    target_workspace: Optional[Path] = None,
    progress_callback: Optional[Callable[[str, int, int], None]] = None,
) -> Tuple[Path, VaultManifest]:
    """
    Authenticates, unlocks, and decrypts a vault into an isolated staging workspace.
    
    Returns:
        (workspace_path, manifest)
    """
    vault_dir = vault_dir.resolve()
    meta_path = vault_dir / META_FILENAME
    metadata = read_vault_metadata(meta_path)

    # Check lock status
    lock_file = vault_dir / STATE_LOCK_FILENAME
    if lock_file.is_file():
        try:
            with open(lock_file, "r", encoding="utf-8") as lf:
                lock_data = json.load(lf)
                if lock_data.get("state") == TransactionState.OPEN.value:
                    existing_ws = lock_data.get("workspace_path")
                    raise VaultOperationError(
                        f"Vault is already OPEN (PID: {lock_data.get('pid')}) at workspace: {existing_ws}"
                    )
        except (json.JSONDecodeError, OSError):
            pass

    # Authenticate and derive key
    master_key = unlock_vault_metadata(metadata, password)

    try:
        # Record lock -> DECRYPTING
        record_vault_lock(vault_dir, metadata.vault_id, TransactionState.DECRYPTING)

        manifest = read_encrypted_manifest(vault_dir, metadata.vault_id, master_key)
        objects_dir = vault_dir / OBJECTS_DIRNAME

        # Workspace destination
        if target_workspace:
            workspace_dir = target_workspace.resolve()
        else:
            workspace_dir = get_default_workspaces_dir() / f"{metadata.vault_name}_{metadata.vault_id[:8]}"

        workspace_dir.mkdir(parents=True, exist_ok=True)

        snapshot = WorkspaceSnapshot(
            vault_id=metadata.vault_id,
            vault_dir=str(vault_dir),
            opened_at=time.time(),
        )

        total_files = manifest.get_file_count()
        processed_files = 0

        # Step 1: Create directories first
        for rel_path, entry in manifest.entries.items():
            if entry.is_dir:
                dest_dir = validate_workspace_containment(workspace_dir, rel_path)
                dest_dir.mkdir(parents=True, exist_ok=True)
                snapshot.files[rel_path] = FileSnapshot(
                    rel_path=rel_path,
                    is_dir=True,
                    size_bytes=0,
                    modified_at=entry.modified_at,
                )

        # Step 2: Decrypt files
        for rel_path, entry in manifest.entries.items():
            if entry.is_dir:
                continue

            dest_file = validate_workspace_containment(workspace_dir, rel_path)
            dest_file.parent.mkdir(parents=True, exist_ok=True)

            obj_subpath = get_object_rel_path(entry.object_id)
            obj_full_path = objects_dir / obj_subpath

            if not obj_full_path.is_file():
                raise VaultOperationError(f"Missing encrypted object for file: {rel_path}")

            aad = f"object:{metadata.vault_id}:{entry.object_id}".encode("utf-8")

            with open(obj_full_path, "rb") as in_f, open(dest_file, "wb") as out_f:
                decrypt_stream(in_f, out_f, master_key.raw, associated_data=aad)
                out_f.flush()
                os.fsync(out_f.fileno())

            # Restore original modification time if available
            if entry.modified_at > 0:
                try:
                    os.utime(dest_file, (entry.modified_at, entry.modified_at))
                except OSError:
                    pass

            # Record baseline snapshot
            snapshot.files[rel_path] = FileSnapshot(
                rel_path=rel_path,
                is_dir=False,
                size_bytes=entry.size_bytes,
                modified_at=dest_file.stat().st_mtime,
                sha256_hash=entry.plaintext_sha256,
            )

            processed_files += 1
            if progress_callback:
                progress_callback(rel_path, processed_files, total_files)

        # Save snapshot file in workspace root
        snapshot.save_to_file(workspace_dir / SNAPSHOT_FILENAME)

        # Transition lock state -> OPEN
        record_vault_lock(
            vault_dir,
            metadata.vault_id,
            TransactionState.OPEN,
            workspace_path=str(workspace_dir),
        )

        return workspace_dir, manifest

    except Exception as exc:
        record_vault_lock(vault_dir, metadata.vault_id, TransactionState.RECOVERY_REQUIRED)
        raise VaultOperationError(f"Failed to open vault workspace: {exc}") from exc
    finally:
        master_key.zeroize()


def detect_workspace_changes(
    workspace_dir: Path,
    snapshot: WorkspaceSnapshot,
) -> Tuple[Set[str], Set[str], Set[str]]:
    """
    Compares current workspace contents against the snapshot.
    Returns:
        (added_files, modified_files, deleted_files) as sets of sanitized relative paths.
    """
    current_files: Dict[str, Path] = {}
    
    for root, dirs, files in os.walk(workspace_dir):
        for f in files:
            if f == SNAPSHOT_FILENAME:
                continue
            abs_p = Path(root) / f
            rel_p = sanitize_vault_relative_path(str(abs_p.relative_to(workspace_dir)))
            current_files[rel_p] = abs_p

    snapshot_file_paths = {k for k, v in snapshot.files.items() if not v.is_dir}
    current_paths = set(current_files.keys())

    added = current_paths - snapshot_file_paths
    deleted = snapshot_file_paths - current_paths
    modified: Set[str] = set()

    for p in current_paths & snapshot_file_paths:
        snap_item = snapshot.files[p]
        abs_p = current_files[p]
        st = abs_p.stat()
        
        # Fast check: size or mtime differs
        if st.st_size != snap_item.size_bytes or abs(st.st_mtime - snap_item.modified_at) > 0.001:
            # Check SHA-256 to confirm content change
            current_hash = compute_file_sha256(abs_p)
            if current_hash != snap_item.sha256_hash:
                modified.add(p)

    return added, modified, deleted


def close_vault_workspace(
    workspace_dir: Path,
    password: str,
    progress_callback: Optional[Callable[[str, int, int], None]] = None,
) -> None:
    """
    Performs differential re-encryption of workspace changes back into the vault,
    updates manifest.enc, and securely shreds the workspace.
    """
    workspace_dir = workspace_dir.resolve()
    snapshot_path = workspace_dir / SNAPSHOT_FILENAME
    if not snapshot_path.is_file():
        raise VaultOperationError(f"Missing snapshot file {SNAPSHOT_FILENAME} in workspace: {workspace_dir}")

    snapshot = WorkspaceSnapshot.load_from_file(snapshot_path)
    vault_dir = Path(snapshot.vault_dir).resolve()
    meta_path = vault_dir / META_FILENAME
    metadata = read_vault_metadata(meta_path)

    # Derive master key
    master_key = unlock_vault_metadata(metadata, password)

    try:
        # Record lock -> CLOSING
        record_vault_lock(vault_dir, metadata.vault_id, TransactionState.CLOSING, str(workspace_dir))

        # Detect changes
        added, modified, deleted = detect_workspace_changes(workspace_dir, snapshot)
        manifest = read_encrypted_manifest(vault_dir, metadata.vault_id, master_key)
        objects_dir = vault_dir / OBJECTS_DIRNAME

        # Handle deleted files
        for p in deleted:
            entry = manifest.remove_entry(p)
            if entry and entry.object_id:
                obj_file = objects_dir / get_object_rel_path(entry.object_id)
                if obj_file.is_file():
                    try:
                        obj_file.unlink()
                    except OSError:
                        pass

        # Handle added and modified files (differential encryption)
        files_to_update = added | modified
        total_updates = len(files_to_update)
        current_idx = 0

        for rel_path in files_to_update:
            abs_p = workspace_dir / rel_path
            st = abs_p.stat()
            new_obj_id = str(uuid.uuid4())
            new_obj_subpath = get_object_rel_path(new_obj_id)
            new_obj_full = objects_dir / new_obj_subpath
            new_obj_full.parent.mkdir(parents=True, exist_ok=True)

            hasher = hashlib.sha256()

            with open(abs_p, "rb") as in_f, open(new_obj_full, "wb") as out_f:
                class HashingReader:
                    def __init__(self, s, h):
                        self._s = s
                        self._h = h
                    def read(self, n=-1):
                        chunk = self._s.read(n)
                        if chunk:
                            self._h.update(chunk)
                        return chunk
                    def seek(self, offset, whence=0):
                        return self._s.seek(offset, whence)

                hashing_reader = HashingReader(in_f, hasher)
                aad = f"object:{metadata.vault_id}:{new_obj_id}".encode("utf-8")
                encrypt_stream(hashing_reader, out_f, master_key.raw, associated_data=aad)
                out_f.flush()
                os.fsync(out_f.fileno())

            # Delete old object if modifying existing entry
            existing_entry = manifest.entries.get(rel_path)
            if existing_entry and existing_entry.object_id:
                old_obj = objects_dir / get_object_rel_path(existing_entry.object_id)
                if old_obj.is_file():
                    try:
                        old_obj.unlink()
                    except OSError:
                        pass

            # Update manifest entry
            manifest.add_entry(ManifestEntry(
                rel_path=rel_path,
                is_dir=False,
                size_bytes=st.st_size,
                plaintext_sha256=hasher.hexdigest(),
                object_id=new_obj_id,
                created_at=st.st_ctime,
                modified_at=st.st_mtime,
                file_mode=st.st_mode,
            ))

            current_idx += 1
            if progress_callback:
                progress_callback(rel_path, current_idx, total_updates)

        # Write updated encrypted manifest
        write_encrypted_manifest(vault_dir, manifest, master_key)

        # Step: Shred workspace
        record_vault_lock(vault_dir, metadata.vault_id, TransactionState.WIPING_WORKSPACE)
        if snapshot_path.is_file():
            snapshot_path.unlink()
        secure_wipe_directory(workspace_dir, delete_root=True)

        # Finalize -> CLOSED
        remove_vault_lock(vault_dir)

    except Exception as exc:
        record_vault_lock(vault_dir, metadata.vault_id, TransactionState.RECOVERY_REQUIRED)
        raise VaultOperationError(f"Failed to close vault workspace: {exc}") from exc
    finally:
        master_key.zeroize()


def panic_lock_all_workspaces() -> List[str]:
    """
    Emergency lockdown: Finds all active workspaces in ~/.hide/workspaces and
    immediately shreds them, marking associated vaults as PANIC_LOCKED.
    Returns list of locked vault names/workspaces.
    """
    workspaces_dir = get_default_workspaces_dir()
    locked_items = []

    if not workspaces_dir.exists():
        return locked_items

    for item in workspaces_dir.iterdir():
        if item.is_dir():
            snap_path = item / SNAPSHOT_FILENAME
            if snap_path.is_file():
                try:
                    snapshot = WorkspaceSnapshot.load_from_file(snap_path)
                    v_dir = Path(snapshot.vault_dir)
                    if v_dir.exists():
                        record_vault_lock(v_dir, snapshot.vault_id, TransactionState.PANIC_LOCKED)
                except Exception:
                    pass
            # Securely shred workspace directory
            secure_wipe_directory(item, delete_root=True)
            locked_items.append(item.name)

    return locked_items
