"""
Tests for Vault Metadata and Disk Persistence (Phase 5).
"""

import json
from pathlib import Path
import pytest
from hide.core.metadata import (
    initialize_vault_metadata,
    write_vault_metadata_atomic,
    read_vault_metadata,
    unlock_vault_metadata,
    CorruptedMetadataError,
    IncompatibleVaultVersionError,
    CURRENT_FORMAT_VERSION,
    META_FILENAME,
)
from hide.core.kdf import InvalidPasswordError


def test_initialize_and_persist_metadata(tmp_path: Path):
    vault_dir = tmp_path / "MyVault.hide"
    meta_path = vault_dir / META_FILENAME
    password = "SuperSecurePassword123!"

    # Initialize metadata
    meta, master_key = initialize_vault_metadata("MyVault", password)
    assert meta.vault_name == "MyVault"
    assert meta.format_version == CURRENT_FORMAT_VERSION
    assert meta.cipher == "aes-256-gcm"
    assert meta.auth_check.tag_b64 != ""

    # Atomic write to disk
    write_vault_metadata_atomic(meta_path, meta)
    assert meta_path.is_file()

    # Read back from disk
    loaded_meta = read_vault_metadata(meta_path)
    assert loaded_meta.vault_id == meta.vault_id
    assert loaded_meta.vault_name == meta.vault_name

    # Unlock with valid password
    with unlock_vault_metadata(loaded_meta, password) as unlocked_key:
        assert unlocked_key.raw == master_key.raw

    # Clean up master key
    master_key.zeroize()


def test_unlock_with_wrong_password(tmp_path: Path):
    meta, master_key = initialize_vault_metadata("VaultX", "RightPassword")
    master_key.zeroize()

    with pytest.raises(InvalidPasswordError):
        unlock_vault_metadata(meta, "WrongPassword")


def test_incompatible_future_version(tmp_path: Path):
    meta_path = tmp_path / META_FILENAME
    meta, master_key = initialize_vault_metadata("FutureVault", "pw")
    master_key.zeroize()

    data = meta.to_dict()
    data["format_version"] = CURRENT_FORMAT_VERSION + 999
    meta_path.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(IncompatibleVaultVersionError):
        read_vault_metadata(meta_path)


def test_corrupted_json(tmp_path: Path):
    meta_path = tmp_path / META_FILENAME
    meta_path.write_text("{ this is not valid json ...", encoding="utf-8")

    with pytest.raises(CorruptedMetadataError):
        read_vault_metadata(meta_path)


def test_missing_fields(tmp_path: Path):
    meta_path = tmp_path / META_FILENAME
    meta_path.write_text(json.dumps({"format_version": 1}), encoding="utf-8")

    with pytest.raises(CorruptedMetadataError):
        read_vault_metadata(meta_path)


def test_nonexistent_file(tmp_path: Path):
    with pytest.raises(FileNotFoundError):
        read_vault_metadata(tmp_path / "does_not_exist.meta")
