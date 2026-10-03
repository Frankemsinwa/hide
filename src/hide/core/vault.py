"""
Vault Operations Engine (Milestone 2: Phases 6 & 7).
Handles:
- `hide init`: Vault container initialization, metadata and manifest setup.
- `hide .` / `hide pack`: Recursive directory scanning, chunked object streaming,
  dry-run verification, atomic manifest commit, and safe removal of original files.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import time
import uuid
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

from hide.core.crypto import (
    AES_KEY_SIZE_BYTES,
    decrypt_stream,
    encrypt_stream,
    generate_secure_bytes,
    DecryptionIntegrityError,
)
from hide.core.kdf import EphemeralKey, derive_key
from hide.core.manifest import (
    MANIFEST_FILENAME,
    read_encrypted_manifest,
    write_encrypted_manifest,
)
from hide.core.metadata import (
    META_FILENAME,
    initialize_vault_metadata,
    read_vault_metadata,
    write_vault_metadata_atomic,
    unlock_vault_metadata,
)
from hide.core.models import (
    EncryptedObjectMeta,
    ManifestEntry,
    TransactionState,
    VaultLockState,
    VaultManifest,
    VaultMetadata,
)
from hide.core.paths import (
    ensure_long_path_support,
    sanitize_vault_relative_path,
)
from hide.core.registry import VaultRegistry

OBJECTS_DIRNAME = "objects"
STATE_LOCK_FILENAME = "state.lock"
JOURNAL_FILENAME = "journal.wal"


class VaultOperationError(Exception):
    """Base error for vault packaging and initialization."""
    pass


class VaultVerificationError(VaultOperationError):
    """Raised when an encrypted object fails verification before original files are removed."""
    pass


def get_object_rel_path(object_id: str) -> str:
    """Generates sharded path 'ab/cdef...enc' for an object UUID."""
    clean_id = object_id.replace("-", "")
    prefix = clean_id[:2]
    rest = clean_id[2:]
    return f"{prefix}/{rest}.enc"


def record_vault_lock(
    vault_dir: Path,
    vault_id: str,
    state: TransactionState,
    workspace_path: Optional[str] = None,
) -> None:
    """Writes the current transaction state into state.lock."""
    lock_file = vault_dir / STATE_LOCK_FILENAME
    lock_data = VaultLockState(
        vault_id=vault_id,
        state=state,
        pid=os.getpid(),
        acquired_at=time.time(),
        workspace_path=workspace_path,
    )
    with open(lock_file, "w", encoding="utf-8") as f:
        json.dump(lock_data.to_dict(), f, indent=2)


def remove_vault_lock(vault_dir: Path) -> None:
    """Removes state.lock once vault transitions to clean state."""
    lock_file = vault_dir / STATE_LOCK_FILENAME
    if lock_file.exists():
        try:
            lock_file.unlink()
        except OSError:
            pass


def init_vault(
    vault_dir: Path,
    name: str,
    password: str,
    registry: Optional[VaultRegistry] = None,
) -> Tuple[VaultMetadata, EphemeralKey]:
    """
    Initializes a new empty encrypted vault directory structure.
    
    Structure created:
    <vault_dir>/
    ├── vault.meta
    ├── manifest.enc
    ├── objects/
    └── journal.wal
    """
    vault_dir = vault_dir.resolve()
    if vault_dir.exists() and any(vault_dir.iterdir()):
        raise VaultOperationError(f"Target directory is not empty: {vault_dir}")

    vault_dir.mkdir(parents=True, exist_ok=True)
    objects_dir = vault_dir / OBJECTS_DIRNAME
    objects_dir.mkdir(parents=True, exist_ok=True)

    metadata, master_key = initialize_vault_metadata(
        vault_name=name,
        password=password,
    )
    meta_path = vault_dir / META_FILENAME
    write_vault_metadata_atomic(meta_path, metadata)

    empty_manifest = VaultManifest(
        vault_id=metadata.vault_id,
        version=1,
        updated_at=time.time(),
    )
    write_encrypted_manifest(vault_dir, empty_manifest, master_key)

    journal_file = vault_dir / JOURNAL_FILENAME
    journal_file.touch()

    # Register in global registry
    reg = registry or VaultRegistry()
    reg.register_vault(vault_dir, name)

    return metadata, master_key


def secure_wipe_file(file_path: Path) -> None:
    """
    Best-effort secure file wipe: overwrites file bytes with zeroes,
    flushes to disk, and removes the file.
    """
    try:
        size = file_path.stat().st_size
        if size > 0:
            with open(file_path, "ba+", buffering=0) as f:
                f.seek(0)
                # Overwrite in 64 KiB chunks
                chunk = b"\x00" * min(size, 65536)
                written = 0
                while written < size:
                    to_write = min(len(chunk), size - written)
                    f.write(chunk[:to_write])
                    written += to_write
                f.flush()
                os.fsync(f.fileno())
        file_path.unlink()
    except Exception:
        # Fallback to direct unlink if write fails
        if file_path.exists():
            file_path.unlink()


def secure_wipe_directory(directory_path: Path, delete_root: bool = False) -> None:
    """
    Recursively overwrites files in a directory and deletes subdirectories.
    """
    for root, dirs, files in os.walk(directory_path, topdown=False):
        for f in files:
            fp = Path(root) / f
            secure_wipe_file(fp)
        for d in dirs:
            dp = Path(root) / d
            try:
                dp.rmdir()
            except OSError:
                pass

    if delete_root and directory_path.exists():
        try:
            directory_path.rmdir()
        except OSError:
            pass


def pack_directory(
    source_dir: Path,
    target_vault_dir: Path,
    vault_name: str,
    password: str,
    delete_original: bool = True,
    progress_callback: Optional[Callable[[str, int, int], None]] = None,
    registry: Optional[VaultRegistry] = None,
) -> VaultMetadata:
    """
    Packs and encrypts an entire folder tree into an encrypted vault.
    
    SAFETY INVARIANT:
    Original source files are NEVER deleted until:
    1. Every file has been encrypted and synced to disk.
    2. Encrypted manifest is written and synced.
    3. Full verification check passes across all encrypted objects.
    """
    source_dir = source_dir.resolve()
    if not source_dir.is_dir():
        raise VaultOperationError(f"Source directory does not exist: {source_dir}")

    target_vault_dir = target_vault_dir.resolve()
    # Check if target is inside source
    try:
        target_vault_dir.relative_to(source_dir)
        raise VaultOperationError("Target vault path cannot be inside the source directory.")
    except ValueError:
        pass

    # Step 1: Scan directory
    items_to_encrypt: List[Tuple[Path, str, bool]] = []
    total_bytes = 0

    for root, dirs, files in os.walk(source_dir):
        for d in dirs:
            abs_dir = Path(root) / d
            rel_dir = sanitize_vault_relative_path(str(abs_dir.relative_to(source_dir)))
            items_to_encrypt.append((abs_dir, rel_dir, True))
        for f in files:
            abs_file = Path(root) / f
            rel_file = sanitize_vault_relative_path(str(abs_file.relative_to(source_dir)))
            size = abs_file.stat().st_size
            total_bytes += size
            items_to_encrypt.append((abs_file, rel_file, False))

    # Step 2: Initialize vault container
    metadata, master_key = init_vault(
        vault_dir=target_vault_dir,
        name=vault_name,
        password=password,
        registry=registry,
    )

    # Step 3: Record lock state -> ENCRYPTING
    record_vault_lock(target_vault_dir, metadata.vault_id, TransactionState.ENCRYPTING)

    manifest = VaultManifest(
        vault_id=metadata.vault_id,
        version=1,
        updated_at=time.time(),
    )

    objects_dir = target_vault_dir / OBJECTS_DIRNAME
    objects_dir.mkdir(parents=True, exist_ok=True)

    bytes_processed = 0

    # Step 4: Stream Encrypt files
    try:
        for abs_path, rel_path, is_dir in items_to_encrypt:
            st = abs_path.stat()
            entry = ManifestEntry(
                rel_path=rel_path,
                is_dir=is_dir,
                size_bytes=0 if is_dir else st.st_size,
                created_at=st.st_ctime,
                modified_at=st.st_mtime,
                file_mode=st.st_mode,
            )

            if not is_dir:
                obj_id = str(uuid.uuid4())
                entry.object_id = obj_id
                obj_subpath = get_object_rel_path(obj_id)
                obj_full_path = objects_dir / obj_subpath
                obj_full_path.parent.mkdir(parents=True, exist_ok=True)

                # Compute SHA256 of plaintext while streaming
                hasher = hashlib.sha256()

                with open(abs_path, "rb") as in_f, open(obj_full_path, "wb") as out_f:
                    # Wrap in_f to update hasher
                    class HashingReader:
                        def __init__(self, stream, h):
                            self._s = stream
                            self._h = h
                        def read(self, n=-1):
                            chunk = self._s.read(n)
                            if chunk:
                                self._h.update(chunk)
                            return chunk
                        def seek(self, offset, whence=0):
                            return self._s.seek(offset, whence)

                    hashing_in = HashingReader(in_f, hasher)
                    aad = f"object:{metadata.vault_id}:{obj_id}".encode("utf-8")
                    encrypt_stream(hashing_in, out_f, master_key.raw, associated_data=aad)
                    out_f.flush()
                    os.fsync(out_f.fileno())

                entry.plaintext_sha256 = hasher.hexdigest()
                bytes_processed += st.st_size
                if progress_callback:
                    progress_callback(rel_path, bytes_processed, total_bytes)

            manifest.add_entry(entry)

        # Step 5: Write encrypted manifest
        write_encrypted_manifest(target_vault_dir, manifest, master_key)

        # Step 6: Integrity Verification (Audit before deleting original)
        record_vault_lock(target_vault_dir, metadata.vault_id, TransactionState.SYNC_VERIFIED)
        verify_vault_integrity(target_vault_dir, metadata.vault_id, master_key)

        # Step 7: Safe Deletion of original source files
        if delete_original:
            secure_wipe_directory(source_dir, delete_root=False)

        # Step 8: Finalize lock state -> CLOSED
        remove_vault_lock(target_vault_dir)

        # Update registry metrics
        reg = registry or VaultRegistry()
        reg.register_vault(target_vault_dir, vault_name)

        return metadata

    except Exception as exc:
        record_vault_lock(target_vault_dir, metadata.vault_id, TransactionState.RECOVERY_REQUIRED)
        raise VaultOperationError(f"Encryption failed or aborted: {exc}") from exc
    finally:
        master_key.zeroize()


def verify_vault_integrity(
    vault_dir: Path,
    vault_id: str,
    key: EphemeralKey,
) -> bool:
    """
    Performs full cryptographic audit of all objects against the manifest.
    Verifies GCM authentication tags for every chunk of every object without unpacking.
    """
    manifest = read_encrypted_manifest(vault_dir, vault_id, key)
    objects_dir = vault_dir / OBJECTS_DIRNAME

    for rel_path, entry in manifest.entries.items():
        if entry.is_dir:
            continue
        
        obj_subpath = get_object_rel_path(entry.object_id)
        obj_full_path = objects_dir / obj_subpath

        if not obj_full_path.is_file():
            raise VaultVerificationError(f"Missing encrypted object for file: {rel_path}")

        # Stream decrypt into a null sink while verifying SHA256 and GCM MAC tags
        hasher = hashlib.sha256()
        aad = f"object:{vault_id}:{entry.object_id}".encode("utf-8")

        class VerificationSink:
            def __init__(self, h):
                self._h = h
                self.count = 0
            def write(self, data):
                self._h.update(data)
                self.count += len(data)
            def flush(self):
                pass

        sink = VerificationSink(hasher)
        try:
            with open(obj_full_path, "rb") as in_f:
                decrypt_stream(in_f, sink, key.raw, associated_data=aad)
        except DecryptionIntegrityError as exc:
            raise VaultVerificationError(
                f"Tampering detected! Object verification failed for '{rel_path}': {exc}"
            ) from exc

        if hasher.hexdigest() != entry.plaintext_sha256:
            raise VaultVerificationError(
                f"SHA256 checksum mismatch for '{rel_path}'. Expected {entry.plaintext_sha256}, got {hasher.hexdigest()}"
            )

    return True
