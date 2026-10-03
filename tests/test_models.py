"""
Tests for Core Domain Models (Phase 1).
"""

import time
import uuid
from hide.core.models import (
    VaultMetadata,
    KdfParameters,
    AuthCheckToken,
    ManifestEntry,
    VaultManifest,
    TransactionState,
    VaultLockState,
)


def test_vault_metadata_roundtrip():
    kdf = KdfParameters(
        algorithm="argon2id",
        salt_b64="c2FsdF9leGFtcGxlXzEyMzQ1Njc4OTA=",
        memory_cost_kib=65536,
        time_cost=3,
        parallelism=4,
    )
    auth_check = AuthCheckToken(
        nonce_b64="bm9uY2VfZXhhbXBsZQ==",
        ciphertext_b64="Y2lwaGVydGV4dF9leGFtcGxl",
        tag_b64="dGFnX2V4YW1wbGU=",
    )
    meta = VaultMetadata(
        format_version=1,
        vault_id=str(uuid.uuid4()),
        vault_name="TestVault",
        created_at_utc=time.time(),
        cipher="aes-256-gcm",
        kdf=kdf,
        auth_check=auth_check,
    )

    json_str = meta.to_json()
    reconstructed = VaultMetadata.from_json(json_str)

    assert reconstructed.vault_id == meta.vault_id
    assert reconstructed.vault_name == "TestVault"
    assert reconstructed.kdf.memory_cost_kib == 65536
    assert reconstructed.auth_check.tag_b64 == "dGFnX2V4YW1wbGU="


def test_manifest_entries_and_metrics():
    manifest = VaultManifest(
        vault_id="v-1234",
        version=1,
        updated_at=time.time(),
    )
    
    file1 = ManifestEntry(
        rel_path="documents/report.pdf",
        is_dir=False,
        size_bytes=1048576,
        plaintext_sha256="abc123def456",
        object_id="obj-001",
    )
    file2 = ManifestEntry(
        rel_path="images/photo.png",
        is_dir=False,
        size_bytes=2097152,
        plaintext_sha256="999888777",
        object_id="obj-002",
    )
    dir_entry = ManifestEntry(
        rel_path="documents",
        is_dir=True,
    )

    manifest.add_entry(file1)
    manifest.add_entry(file2)
    manifest.add_entry(dir_entry)

    assert manifest.get_file_count() == 2
    assert manifest.get_total_size() == 3145728

    json_data = manifest.to_json()
    reconstructed = VaultManifest.from_json(json_data)
    assert reconstructed.get_file_count() == 2
    assert reconstructed.entries["images/photo.png"].size_bytes == 2097152


def test_lock_state():
    state = VaultLockState(
        vault_id="v-123",
        state=TransactionState.OPEN,
        pid=12345,
        acquired_at=time.time(),
        workspace_path="C:/temp/workspace_v123",
    )
    data = state.to_dict()
    restored = VaultLockState.from_dict(data)
    assert restored.state == TransactionState.OPEN
    assert restored.pid == 12345
