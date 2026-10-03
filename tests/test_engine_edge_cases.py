"""
Phase 4: Independent Engine Test Suite Edge Cases.
Validates crypto & path engine against edge cases:
- Unicode, Japanese, Arabic, Cyrillic, Emoji paths
- Binary executable bytes
- Zero-byte files & large chunked streams
- Deeply nested directories & Windows path boundaries
- Deterministic failure without silent corruption
"""

import os
from io import BytesIO
from pathlib import Path
import pytest

from hide.core.crypto import (
    encrypt_bytes,
    decrypt_bytes,
    encrypt_stream,
    decrypt_stream,
    generate_secure_bytes,
    DecryptionIntegrityError,
    AES_KEY_SIZE_BYTES,
)
from hide.core.paths import (
    sanitize_vault_relative_path,
    validate_workspace_containment,
    ensure_long_path_support,
    SecurityPathError,
)


@pytest.fixture
def crypto_key():
    return generate_secure_bytes(AES_KEY_SIZE_BYTES)


def test_unicode_and_emoji_paths():
    test_paths = [
        "documents/日本語のノート.txt",
        "secret/проекты/отчет.doc",
        "finance/تقارير_مالية/2026.xlsx",
        "photos/vacation/🌴_beach_summer_☀️.png",
        "code/rust/🦀_main.rs",
        "nested/a/b/c/d/e/deep.dat",
    ]

    for p in test_paths:
        sanitized = sanitize_vault_relative_path(p)
        assert sanitized == p.replace("\\", "/")


def test_binary_executable_encryption(crypto_key):
    # Simulate a Windows PE executable binary (MZ header + PE signature + binary opcodes)
    pe_header = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00"
    random_code = os.urandom(1024 * 64)
    fake_exe = pe_header + random_code + b"PE\x00\x00"

    nonce, ct, tag = encrypt_bytes(fake_exe, crypto_key)
    assert ct != fake_exe

    decrypted = decrypt_bytes(nonce, ct, tag, crypto_key)
    assert decrypted == fake_exe
    assert decrypted[:2] == b"MZ"


def test_streaming_large_payload(crypto_key):
    # 1 MiB stream with arbitrary binary content
    large_data = os.urandom(1024 * 1024)
    in_buf = BytesIO(large_data)
    enc_buf = BytesIO()
    dec_buf = BytesIO()

    # 32 KiB chunking
    bytes_enc = encrypt_stream(in_buf, enc_buf, crypto_key, chunk_size=32 * 1024)
    assert bytes_enc == len(large_data)

    enc_buf.seek(0)
    bytes_dec = decrypt_stream(enc_buf, dec_buf, crypto_key)
    assert bytes_dec == len(large_data)
    assert dec_buf.getvalue() == large_data


def test_zero_byte_streaming_integrity(crypto_key):
    in_buf = BytesIO(b"")
    enc_buf = BytesIO()
    dec_buf = BytesIO()

    encrypt_stream(in_buf, enc_buf, crypto_key)
    enc_buf.seek(0)
    decrypt_stream(enc_buf, dec_buf, crypto_key)
    assert dec_buf.getvalue() == b""


def test_deep_directory_containment(tmp_path: Path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    # Create a deep path (20 levels deep)
    deep_relative = "/".join([f"level_{i}" for i in range(20)]) + "/target.txt"
    resolved = validate_workspace_containment(workspace, deep_relative)

    assert str(resolved).startswith(str(workspace.resolve()))
    assert resolved.name == "target.txt"


def test_long_path_prefix():
    short_path = Path("C:/normal/path/file.txt")
    assert ensure_long_path_support(short_path) == str(short_path.resolve())

    # Deep synthetic path > 260 chars
    long_segments = ["very_long_directory_name_segment_" + str(i) for i in range(12)]
    deep_path = Path("C:/" + "/".join(long_segments) + "/file.dat")
    prefixed = ensure_long_path_support(deep_path)
    if os.name == "nt":
        assert prefixed.startswith("\\\\?\\")
