"""
Vault Metadata, Format Specification, and Disk Persistence (Phase 5).
Manages vault.meta creation, atomic serialization, disk storage, and validation.
"""

from __future__ import annotations

import json
import os
import tempfile
import time
import uuid
from pathlib import Path
from typing import Optional, Tuple

from hide.core.crypto import AES_KEY_SIZE_BYTES
from hide.core.kdf import (
    EphemeralKey,
    create_auth_check_token,
    derive_key,
    generate_new_kdf_params,
    verify_password_and_derive_key,
)
from hide.core.models import (
    AuthCheckToken,
    KdfParameters,
    VaultMetadata,
)

CURRENT_FORMAT_VERSION = 1
CIPHER_SUITE_AES_256_GCM = "aes-256-gcm"
META_FILENAME = "vault.meta"


class MetadataError(Exception):
    """Base exception for metadata handling."""
    pass


class IncompatibleVaultVersionError(MetadataError):
    """Raised when vault format version is higher than supported."""
    pass


class CorruptedMetadataError(MetadataError):
    """Raised when metadata file is missing required fields or corrupted."""
    pass


def initialize_vault_metadata(
    vault_name: str,
    password: str,
    vault_id: Optional[str] = None,
    memory_cost_kib: Optional[int] = None,
    time_cost: Optional[int] = None,
    parallelism: Optional[int] = None,
) -> Tuple[VaultMetadata, EphemeralKey]:
    """
    Initializes a new VaultMetadata instance with Argon2id parameters
    and an encrypted authentication check token.
    
    Returns:
        (VaultMetadata, EphemeralKey): The created metadata and the active derived key.
    """
    if not vault_name or not vault_name.strip():
        raise ValueError("Vault name cannot be empty.")
    if not password:
        raise ValueError("Password cannot be empty.")

    v_id = vault_id or str(uuid.uuid4())
    
    kwargs = {}
    if memory_cost_kib is not None:
        kwargs["memory_cost_kib"] = memory_cost_kib
    if time_cost is not None:
        kwargs["time_cost"] = time_cost
    if parallelism is not None:
        kwargs["parallelism"] = parallelism

    kdf_params = generate_new_kdf_params(**kwargs)
    master_key = derive_key(password, kdf_params)

    auth_token = create_auth_check_token(master_key, v_id)

    metadata = VaultMetadata(
        format_version=CURRENT_FORMAT_VERSION,
        vault_id=v_id,
        vault_name=vault_name.strip(),
        created_at_utc=time.time(),
        cipher=CIPHER_SUITE_AES_256_GCM,
        kdf=kdf_params,
        auth_check=auth_token,
    )

    return metadata, master_key


def write_vault_metadata_atomic(meta_path: Path, metadata: VaultMetadata) -> None:
    """
    Atomically writes vault.meta to disk using a write-flush-replace strategy
    to guarantee that a crash during writing never leaves a corrupt or half-written metadata file.
    """
    target_path = meta_path.resolve()
    parent_dir = target_path.parent
    parent_dir.mkdir(parents=True, exist_ok=True)

    json_data = metadata.to_json(indent=2).encode("utf-8")

    # Write to a temporary file in the same directory (so rename is atomic on POSIX and Windows NTFS)
    tmp_fd, tmp_file_path = tempfile.mkstemp(prefix="meta_", suffix=".tmp", dir=str(parent_dir))
    try:
        with os.fdopen(tmp_fd, "wb") as f:
            f.write(json_data)
            f.flush()
            os.fsync(f.fileno())  # Force sync to physical disk storage
        
        # Atomically replace target
        os.replace(tmp_file_path, target_path)
    except Exception as exc:
        if os.path.exists(tmp_file_path):
            try:
                os.remove(tmp_file_path)
            except OSError:
                pass
        raise MetadataError(f"Failed to write vault metadata atomically: {exc}") from exc


def read_vault_metadata(meta_path: Path) -> VaultMetadata:
    """
    Reads and validates vault.meta from disk.
    
    Raises:
        FileNotFoundError: If meta file does not exist.
        IncompatibleVaultVersionError: If format version is not supported.
        CorruptedMetadataError: If JSON is invalid or fields are missing.
    """
    path = meta_path.resolve()
    if not path.is_file():
        raise FileNotFoundError(f"Vault metadata not found at: {path}")

    try:
        with open(path, "r", encoding="utf-8") as f:
            raw_text = f.read()
    except Exception as exc:
        raise CorruptedMetadataError(f"Cannot read metadata file: {exc}") from exc

    try:
        data = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise CorruptedMetadataError(f"Malformed JSON in vault metadata: {exc}") from exc

    if not isinstance(data, dict):
        raise CorruptedMetadataError("Metadata root must be a JSON object.")

    version = data.get("format_version")
    if version is None:
        raise CorruptedMetadataError("Missing format_version in vault metadata.")
    if version > CURRENT_FORMAT_VERSION:
        raise IncompatibleVaultVersionError(
            f"Vault format version {version} is newer than supported version {CURRENT_FORMAT_VERSION}."
        )

    try:
        return VaultMetadata.from_dict(data)
    except (KeyError, TypeError, ValueError) as exc:
        raise CorruptedMetadataError(f"Metadata is missing required fields or has invalid types: {exc}") from exc


def unlock_vault_metadata(metadata: VaultMetadata, password: str) -> EphemeralKey:
    """
    Verifies the password against the metadata's auth check token and derives the active key.
    
    Returns:
        EphemeralKey ready for vault decryption.
        
    Raises:
        InvalidPasswordError: If the password is incorrect.
    """
    return verify_password_and_derive_key(
        password=password,
        params=metadata.kdf,
        auth_check=metadata.auth_check,
        vault_id=metadata.vault_id,
    )
