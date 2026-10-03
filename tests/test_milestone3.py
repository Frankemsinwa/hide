"""
Tests for Milestone 3 (Phases 9–14):
- Phase 9: hide open & temporary workspace staging
- Phase 10: Differential change detection & re-encryption
- Phase 11: Transactional crash recovery
- Phase 12: Secure workspace wipe
- Phase 13: hide close, hide lock, hide status
- Phase 14: Emergency lock (hide panic)
"""

import os
from pathlib import Path
import pytest
from click.testing import CliRunner

from hide.cli import cli
from hide.core.models import TransactionState
from hide.core.registry import VaultRegistry
from hide.core.vault import pack_directory, verify_vault_integrity
from hide.core.kdf import derive_key
from hide.core.workspace import (
    open_vault_workspace,
    close_vault_workspace,
    detect_workspace_changes,
    panic_lock_all_workspaces,
    WorkspaceSnapshot,
    SNAPSHOT_FILENAME,
)
from hide.core.recovery import (
    get_vault_operational_status,
    recover_interrupted_vault,
)


@pytest.fixture
def sample_vault(tmp_path: Path):
    source_dir = tmp_path / "SourceFiles"
    source_dir.mkdir()
    (source_dir / "doc.txt").write_text("Original document content", encoding="utf-8")
    (source_dir / "to_delete.txt").write_text("Will be deleted", encoding="utf-8")

    vault_dir = tmp_path / "TestVault.hide"
    registry = VaultRegistry(tmp_path / "registry.json")
    password = "VaultPassword123!"

    pack_directory(
        source_dir=source_dir,
        target_vault_dir=vault_dir,
        vault_name="TestVault",
        password=password,
        delete_original=False,
        registry=registry,
    )

    return vault_dir, password, registry


def test_open_and_close_vault_workspace(sample_vault, tmp_path: Path):
    vault_dir, password, registry = sample_vault
    staging_ws = tmp_path / "custom_staging"

    # Phase 9: Open vault workspace
    ws_dir, manifest = open_vault_workspace(
        vault_dir=vault_dir,
        password=password,
        target_workspace=staging_ws,
    )

    assert ws_dir == staging_ws
    assert (staging_ws / "doc.txt").read_text(encoding="utf-8") == "Original document content"
    assert (staging_ws / SNAPSHOT_FILENAME).is_file()

    # Verify lock state is OPEN
    status, lock = get_vault_operational_status(vault_dir)
    assert status == TransactionState.OPEN

    # Phase 10: Modify workspace
    # 1. Edit existing file
    (staging_ws / "doc.txt").write_text("Updated document content!", encoding="utf-8")
    # 2. Add new file
    (staging_ws / "new_file.txt").write_text("Brand new file", encoding="utf-8")
    # 3. Delete file
    (staging_ws / "to_delete.txt").unlink()

    snapshot = WorkspaceSnapshot.load_from_file(staging_ws / SNAPSHOT_FILENAME)
    added, modified, deleted = detect_workspace_changes(staging_ws, snapshot)

    assert "new_file.txt" in added
    assert "doc.txt" in modified
    assert "to_delete.txt" in deleted

    # Phase 13: Close workspace
    close_vault_workspace(staging_ws, password)

    # Invariant: staging workspace must be shredded
    assert not staging_ws.exists()

    # Vault lock state must be CLOSED
    status, _ = get_vault_operational_status(vault_dir)
    assert status == TransactionState.CLOSED

    # Re-open vault to verify changes survived into vault
    ws_reopened, manifest2 = open_vault_workspace(
        vault_dir=vault_dir,
        password=password,
        target_workspace=staging_ws,
    )

    assert (ws_reopened / "doc.txt").read_text(encoding="utf-8") == "Updated document content!"
    assert (ws_reopened / "new_file.txt").read_text(encoding="utf-8") == "Brand new file"
    assert not (ws_reopened / "to_delete.txt").exists()

    # Clean close
    close_vault_workspace(ws_reopened, password)


def test_crash_recovery(sample_vault, tmp_path: Path):
    vault_dir, password, _ = sample_vault
    staging_ws = tmp_path / "crash_staging"

    open_vault_workspace(vault_dir, password, target_workspace=staging_ws)

    # Simulate a crash: simulate process death by writing non-existent PID (e.g. PID 99999999)
    from hide.core.vault import record_vault_lock
    record_vault_lock(vault_dir, "fake-vault-id", TransactionState.OPEN, str(staging_ws))
    
    # Overwrite with dead PID
    lock_file = vault_dir / "state.lock"
    lock_file.write_text(
        '{"vault_id": "test", "state": "OPEN", "pid": 99999999, "acquired_at": 1000.0, "workspace_path": "'
        + str(staging_ws).replace("\\", "/")
        + '"}',
        encoding="utf-8",
    )

    status, lock = get_vault_operational_status(vault_dir)
    assert status == TransactionState.RECOVERY_REQUIRED

    # Run recovery
    msg = recover_interrupted_vault(vault_dir)
    assert "Recovery complete" in msg

    # Workspace should still exist safely
    assert staging_ws.is_dir()
    assert (staging_ws / "doc.txt").is_file()

    # Close workspace cleanly
    close_vault_workspace(staging_ws, password)


def test_panic_emergency_lock(sample_vault):
    vault_dir, password, _ = sample_vault
    # Open into default ~/.hide/workspaces
    ws_dir, _ = open_vault_workspace(vault_dir, password)
    assert ws_dir.is_dir()

    # Emergency panic
    shredded = panic_lock_all_workspaces()
    assert len(shredded) >= 1

    # Workspace must be gone
    assert not ws_dir.exists()

    # Vault status must be PANIC_LOCKED
    status, _ = get_vault_operational_status(vault_dir)
    assert status == TransactionState.PANIC_LOCKED


def test_cli_status(sample_vault):
    vault_dir, _, registry = sample_vault
    runner = CliRunner()
    result = runner.invoke(cli, ["status", str(vault_dir)])
    assert result.exit_code == 0
    assert "TestVault" in result.output
    assert "CLOSED" in result.output
