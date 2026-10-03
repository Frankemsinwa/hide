"""
Tests for Path Validation and Traversal Defense (Phase 1).
"""

import pytest
from pathlib import Path
from hide.core.paths import (
    sanitize_vault_relative_path,
    validate_workspace_containment,
    is_safe_file_name,
    SecurityPathError,
)


def test_safe_relative_paths():
    assert sanitize_vault_relative_path("notes.txt") == "notes.txt"
    assert sanitize_vault_relative_path("docs/secret/plan.pdf") == "docs/secret/plan.pdf"
    assert sanitize_vault_relative_path("nested\\subfolder\\file.dat") == "nested/subfolder/file.dat"
    assert sanitize_vault_relative_path("./local/path/file.py") == "local/path/file.py"


def test_reject_path_traversal():
    with pytest.raises(SecurityPathError, match="Path traversal"):
        sanitize_vault_relative_path("../escape.txt")

    with pytest.raises(SecurityPathError, match="Path traversal"):
        sanitize_vault_relative_path("docs/../../system32/cmd.exe")

    with pytest.raises(SecurityPathError, match="Absolute paths"):
        sanitize_vault_relative_path("C:/Windows/notepad.exe")

    with pytest.raises(SecurityPathError, match="Absolute paths"):
        sanitize_vault_relative_path("/etc/passwd")


def test_reject_alternate_data_streams():
    with pytest.raises(SecurityPathError, match="Alternate Data Stream"):
        sanitize_vault_relative_path("hidden.txt:secret_stream")


def test_reject_windows_reserved_device_names():
    assert not is_safe_file_name("CON")
    assert not is_safe_file_name("NUL.txt")
    assert not is_safe_file_name("com1")

    with pytest.raises(SecurityPathError, match="Forbidden or reserved"):
        sanitize_vault_relative_path("data/NUL/secret.txt")


def test_workspace_containment(tmp_path: Path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    safe_target = validate_workspace_containment(workspace, "sub/dir/file.txt")
    assert safe_target == (workspace / "sub" / "dir" / "file.txt").resolve()

    with pytest.raises(SecurityPathError):
        validate_workspace_containment(workspace, "../../outside.txt")
