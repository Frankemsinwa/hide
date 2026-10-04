"""
Tests for Milestone 2 (Phases 6–8):
- Phase 6: hide init & container creation
- Phase 7: hide . / hide pack & in-place encryption with safe deletion
- Phase 8: hide list & global vault registry
"""

import json
import os
from pathlib import Path
import pytest
from click.testing import CliRunner

from hide.cli import cli
from hide.core.crypto import AES_KEY_SIZE_BYTES
from hide.core.manifest import read_encrypted_manifest
from hide.core.metadata import read_vault_metadata, META_FILENAME
from hide.core.models import TransactionState
from hide.core.registry import VaultRegistry
from hide.core.vault import (
    init_vault,
    pack_directory,
    verify_vault_integrity,
    OBJECTS_DIRNAME,
    MANIFEST_FILENAME,
    VaultVerificationError,
)
from hide.core.kdf import derive_key


def test_init_vault(tmp_path: Path):
    vault_path = tmp_path / "Finance.hide"
    registry_file = tmp_path / "registry.json"
    registry = VaultRegistry(registry_file)

    meta, key = init_vault(
        vault_dir=vault_path,
        name="Finance",
        password="TestPassword123!",
        registry=registry,
    )

    assert (vault_path / META_FILENAME).is_file()
    assert (vault_path / MANIFEST_FILENAME).is_file()
    assert (vault_path / OBJECTS_DIRNAME).is_dir()

    # Verify empty manifest was created and can be decrypted
    manifest = read_encrypted_manifest(vault_path, meta.vault_id, key)
    assert manifest.get_file_count() == 0
    key.zeroize()

    # Verify registered in registry
    registered = registry.list_vaults()
    assert len(registered) == 1
    assert registered[0].name == "Finance"
    assert registered[0].status == TransactionState.CLOSED


def test_pack_directory_and_verify(tmp_path: Path):
    source_dir = tmp_path / "MyProject"
    source_dir.mkdir()
    (source_dir / "file1.txt").write_text("Hello World", encoding="utf-8")
    
    sub = source_dir / "subdir"
    sub.mkdir()
    (sub / "nested.dat").write_bytes(b"\x01\x02\x03\x04" * 1024)

    target_vault = tmp_path / "MyProject.hide"
    registry_file = tmp_path / "registry.json"
    registry = VaultRegistry(registry_file)

    password = "ProjectPassword1!"

    # Pack with deletion of originals
    meta = pack_directory(
        source_dir=source_dir,
        target_vault_dir=target_vault,
        vault_name="MyProject",
        password=password,
        delete_original=True,
        registry=registry,
    )

    assert meta.vault_name == "MyProject"
    
    # Invariant: source directory contents must be wiped
    assert not (source_dir / "file1.txt").exists()
    assert not (sub / "nested.dat").exists()

    # Vault container exists
    assert (target_vault / META_FILENAME).is_file()
    assert (target_vault / MANIFEST_FILENAME).is_file()

    # Verify all objects with derived key
    with derive_key(password, meta.kdf) as master_key:
        is_ok = verify_vault_integrity(target_vault, meta.vault_id, master_key)
        assert is_ok is True


def test_pack_directory_keep_flag(tmp_path: Path):
    source_dir = tmp_path / "KeepDir"
    source_dir.mkdir()
    (source_dir / "important.doc").write_text("Do not delete", encoding="utf-8")

    target_vault = tmp_path / "KeepDir.hide"
    registry = VaultRegistry(tmp_path / "registry.json")

    pack_directory(
        source_dir=source_dir,
        target_vault_dir=target_vault,
        vault_name="KeepDir",
        password="pw",
        delete_original=False,  # Keep flag
        registry=registry,
    )

    # Invariant: source file must still exist
    assert (source_dir / "important.doc").is_file()


def test_tamper_detection_in_object_store(tmp_path: Path):
    source_dir = tmp_path / "TamperDir"
    source_dir.mkdir()
    (source_dir / "data.bin").write_bytes(b"sensitive content")

    target_vault = tmp_path / "TamperDir.hide"
    registry = VaultRegistry(tmp_path / "registry.json")
    password = "secret_password"

    meta = pack_directory(
        source_dir=source_dir,
        target_vault_dir=target_vault,
        vault_name="TamperDir",
        password=password,
        delete_original=False,
        registry=registry,
    )

    # Find encrypted object file in objects/
    objects_dir = target_vault / OBJECTS_DIRNAME
    object_files = list(objects_dir.glob("*/*.enc"))
    assert len(object_files) == 1

    # Tamper with 1 byte in the object file
    obj_path = object_files[0]
    corrupted_data = bytearray(obj_path.read_bytes())
    corrupted_data[-1] ^= 0x55  # Tamper with the MAC tag or ciphertext
    obj_path.write_bytes(corrupted_data)

    # Integrity verification must catch the tampering and abort
    with derive_key(password, meta.kdf) as master_key:
        with pytest.raises(VaultVerificationError, match="Tampering detected"):
            verify_vault_integrity(target_vault, meta.vault_id, master_key)


def test_cli_list_empty(monkeypatch, tmp_path: Path):
    empty_reg_file = tmp_path / "empty_registry.json"
    monkeypatch.setattr("hide.cli.VaultRegistry", lambda: VaultRegistry(empty_reg_file))
    runner = CliRunner()
    result = runner.invoke(cli, ["list"])
    assert result.exit_code == 0
    assert "No vaults registered" in result.output


def test_pack_large_multi_chunk_file(tmp_path: Path):
    # Tests a 200 KiB file (spanning multiple 64 KiB chunks) to ensure
    # that streaming hashing has no off-by-one or rewind artifacts
    source_dir = tmp_path / "LargeFileDir"
    source_dir.mkdir()
    large_payload = os.urandom(200 * 1024)
    (source_dir / "large.bin").write_bytes(large_payload)

    target_vault = tmp_path / "LargeFile.hide"
    registry = VaultRegistry(tmp_path / "registry.json")
    password = "pw"

    meta = pack_directory(
        source_dir=source_dir,
        target_vault_dir=target_vault,
        vault_name="LargeFile",
        password=password,
        delete_original=False,
        registry=registry,
    )

    # Verification must pass with exact SHA256 match
    with derive_key(password, meta.kdf) as master_key:
        assert verify_vault_integrity(target_vault, meta.vault_id, master_key) is True
