"""
Encrypted Manifest Management (Phase 6 & 7).
Serializes, encrypts, writes, and reads the vault catalog in manifest.enc.
Conceals all file paths, timestamps, permissions, and directory structures.
"""

from __future__ import annotations

import json
import os
import tempfile
import time
from pathlib import Path
from typing import Optional

from hide.core.crypto import (
    encrypt_payload_envelope,
    decrypt_payload_envelope,
    DecryptionIntegrityError,
    CryptographyError,
)
from hide.core.kdf import EphemeralKey
from hide.core.models import ManifestEntry, VaultManifest

MANIFEST_FILENAME = "manifest.enc"


class ManifestError(Exception):
    """Base error for manifest operations."""
    pass


class ManifestIntegrityError(ManifestError):
    """Raised when manifest ciphertext has been tampered with or key is invalid."""
    pass


def get_manifest_aad(vault_id: str) -> bytes:
    """Derives domain-separated Associated Authenticated Data for manifest encryption."""
    return f"manifest:{vault_id}".encode("utf-8")


def write_encrypted_manifest(
    vault_dir: Path,
    manifest: VaultManifest,
    key: EphemeralKey,
) -> Path:
    """
    Encrypts the VaultManifest with AES-256-GCM and writes it atomically to manifest.enc.
    """
    target_path = (vault_dir / MANIFEST_FILENAME).resolve()
    target_path.parent.mkdir(parents=True, exist_ok=True)

    manifest.updated_at = time.time()
    raw_json = manifest.to_json().encode("utf-8")
    aad = get_manifest_aad(manifest.vault_id)

    envelope = encrypt_payload_envelope(
        plaintext=raw_json,
        key=key.raw,
        associated_data=aad,
    )

    tmp_fd, tmp_file = tempfile.mkstemp(
        prefix="manifest_", suffix=".tmp", dir=str(target_path.parent)
    )
    try:
        with os.fdopen(tmp_fd, "wb") as f:
            f.write(envelope)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_file, target_path)
    except Exception as exc:
        if os.path.exists(tmp_file):
            try:
                os.remove(tmp_file)
            except OSError:
                pass
        raise ManifestError(f"Failed to write encrypted manifest: {exc}") from exc

    return target_path


def read_encrypted_manifest(
    vault_dir: Path,
    vault_id: str,
    key: EphemeralKey,
) -> VaultManifest:
    """
    Reads and decrypts manifest.enc using the provided EphemeralKey.
    
    Raises:
        FileNotFoundError: If manifest.enc does not exist.
        ManifestIntegrityError: If key is wrong or manifest is corrupted/tampered with.
    """
    target_path = (vault_dir / MANIFEST_FILENAME).resolve()
    if not target_path.is_file():
        raise FileNotFoundError(f"Manifest not found at: {target_path}")

    try:
        with open(target_path, "rb") as f:
            envelope = f.read()
    except Exception as exc:
        raise ManifestError(f"Failed to read manifest file: {exc}") from exc

    aad = get_manifest_aad(vault_id)
    try:
        decrypted_json_bytes = decrypt_payload_envelope(
            envelope=envelope,
            key=key.raw,
            associated_data=aad,
        )
    except DecryptionIntegrityError as exc:
        raise ManifestIntegrityError("Manifest integrity verification failed. Wrong key or corrupted data.") from exc
    except Exception as exc:
        raise ManifestError(f"Manifest decryption error: {exc}") from exc

    try:
        json_str = decrypted_json_bytes.decode("utf-8")
        return VaultManifest.from_json(json_str)
    except Exception as exc:
        raise ManifestError(f"Malformed manifest JSON: {exc}") from exc
