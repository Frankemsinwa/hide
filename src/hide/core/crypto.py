"""
Cryptographic Core Engine for Hide Vault.
Provides authenticated encryption (AES-256-GCM) with AEAD,
in-memory encryption/decryption, and chunked streaming encryption
for large files without unbounded memory consumption.
"""

from __future__ import annotations

import os
import struct
from io import BytesIO
from typing import BinaryIO, Generator, Optional, Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# Constants for AES-256-GCM
AES_KEY_SIZE_BYTES = 32      # 256-bit key
GCM_NONCE_SIZE_BYTES = 12    # 96-bit standard nonce
GCM_TAG_SIZE_BYTES = 16      # 128-bit authentication tag

# Streaming chunk size: 64 KiB
DEFAULT_CHUNK_SIZE_BYTES = 64 * 1024

# Stream header magic bytes: 'HIDE_OBJ' + version 1
STREAM_HEADER_MAGIC = b"HIDEOBJ\x01"


class CryptographyError(Exception):
    """Base error for cryptographic operations."""
    pass


class DecryptionIntegrityError(CryptographyError):
    """Raised when authentication tag verification fails (tampering or bad key)."""
    pass


class InvalidCiphertextError(CryptographyError):
    """Raised when ciphertext structure or stream header is malformed."""
    pass


def generate_secure_bytes(num_bytes: int) -> bytes:
    """Generates cryptographically strong random bytes using the OS CSPRNG."""
    return os.urandom(num_bytes)


def encrypt_bytes(
    plaintext: bytes,
    key: bytes,
    associated_data: Optional[bytes] = None,
    nonce: Optional[bytes] = None,
) -> Tuple[bytes, bytes, bytes]:
    """
    Encrypts in-memory plaintext using AES-256-GCM.
    
    Args:
        plaintext: The data bytes to encrypt.
        key: 32-byte (256-bit) encryption key.
        associated_data: Optional authenticated associated data (AAD).
        nonce: Optional 12-byte nonce (if None, a fresh CSPRNG nonce is generated).
        
    Returns:
        (nonce, ciphertext, tag):
            nonce: 12 bytes
            ciphertext: encrypted data (without tag)
            tag: 16 bytes authentication tag
    """
    if len(key) != AES_KEY_SIZE_BYTES:
        raise ValueError(f"AES-256 key must be exactly {AES_KEY_SIZE_BYTES} bytes, got {len(key)}")

    if nonce is None:
        nonce = generate_secure_bytes(GCM_NONCE_SIZE_BYTES)
    elif len(nonce) != GCM_NONCE_SIZE_BYTES:
        raise ValueError(f"AES-GCM nonce must be exactly {GCM_NONCE_SIZE_BYTES} bytes, got {len(nonce)}")

    aesgcm = AESGCM(key)
    # cryptography's AESGCM.encrypt appends the 16-byte tag to the ciphertext
    ct_with_tag = aesgcm.encrypt(nonce, plaintext, associated_data)
    ciphertext = ct_with_tag[:-GCM_TAG_SIZE_BYTES]
    tag = ct_with_tag[-GCM_TAG_SIZE_BYTES:]

    return nonce, ciphertext, tag


def decrypt_bytes(
    nonce: bytes,
    ciphertext: bytes,
    tag: bytes,
    key: bytes,
    associated_data: Optional[bytes] = None,
) -> bytes:
    """
    Decrypts and authenticates in-memory ciphertext using AES-256-GCM.
    
    Args:
        nonce: 12-byte nonce used during encryption.
        ciphertext: Ciphertext data (without tag).
        tag: 16-byte authentication tag.
        key: 32-byte (256-bit) encryption key.
        associated_data: Associated data verified against authentication tag.
        
    Returns:
        plaintext bytes.
        
    Raises:
        DecryptionIntegrityError: If key is incorrect or data/tag has been modified.
        ValueError: If key or nonce length is invalid.
    """
    if len(key) != AES_KEY_SIZE_BYTES:
        raise ValueError(f"AES-256 key must be exactly {AES_KEY_SIZE_BYTES} bytes, got {len(key)}")
    if len(nonce) != GCM_NONCE_SIZE_BYTES:
        raise ValueError(f"AES-GCM nonce must be exactly {GCM_NONCE_SIZE_BYTES} bytes, got {len(nonce)}")
    if len(tag) != GCM_TAG_SIZE_BYTES:
        raise ValueError(f"AES-GCM tag must be exactly {GCM_TAG_SIZE_BYTES} bytes, got {len(tag)}")

    aesgcm = AESGCM(key)
    ct_with_tag = ciphertext + tag
    try:
        plaintext = aesgcm.decrypt(nonce, ct_with_tag, associated_data)
        return plaintext
    except Exception as exc:
        raise DecryptionIntegrityError("Decryption failed: integrity check failed or wrong key.") from exc


def encrypt_payload_envelope(plaintext: bytes, key: bytes, associated_data: Optional[bytes] = None) -> bytes:
    """
    Convenience helper: packages (nonce + ciphertext + tag) into a single byte stream.
    Format: [12 bytes nonce] [16 bytes tag] [ciphertext]
    """
    nonce, ct, tag = encrypt_bytes(plaintext, key, associated_data)
    return nonce + tag + ct


def decrypt_payload_envelope(envelope: bytes, key: bytes, associated_data: Optional[bytes] = None) -> bytes:
    """
    Convenience helper: unpacks [12 bytes nonce] [16 bytes tag] [ciphertext] and decrypts.
    """
    min_len = GCM_NONCE_SIZE_BYTES + GCM_TAG_SIZE_BYTES
    if len(envelope) < min_len:
        raise InvalidCiphertextError(f"Envelope size ({len(envelope)}) too small for nonce + tag.")
    nonce = envelope[:GCM_NONCE_SIZE_BYTES]
    tag = envelope[GCM_NONCE_SIZE_BYTES:min_len]
    ciphertext = envelope[min_len:]
    return decrypt_bytes(nonce, ciphertext, tag, key, associated_data)


# ---------------------------------------------------------------------------
# Chunked Streaming Encryption for Large Files
# ---------------------------------------------------------------------------

def _derive_chunk_nonce(base_nonce: bytes, chunk_index: int) -> bytes:
    """
    Derives a deterministic, unique 12-byte nonce for a specific chunk index
    by XORing the 64-bit chunk index into the final 8 bytes of the base nonce.
    Prevents nonce reuse while keeping storage overhead minimal (single 12-byte base nonce in header).
    """
    index_bytes = struct.pack(">Q", chunk_index)  # 8 bytes big-endian
    nonce_prefix = base_nonce[:4]
    nonce_suffix = bytes(a ^ b for a, b in zip(base_nonce[4:], index_bytes))
    return nonce_prefix + nonce_suffix


def encrypt_stream(
    in_stream: BinaryIO,
    out_stream: BinaryIO,
    key: bytes,
    associated_data: Optional[bytes] = None,
    chunk_size: int = DEFAULT_CHUNK_SIZE_BYTES,
) -> int:
    """
    Streams and encrypts large payloads chunk-by-chunk using AES-256-GCM.
    
    Wire Format:
    - Header:
        - 8 bytes magic ('HIDEOBJ\\x01')
        - 12 bytes base nonce
        - 4 bytes chunk_size (uint32)
    - Per Chunk:
        - 4 bytes payload length (uint32)
        - 1 byte is_final flag (0x00 or 0x01)
        - 16 bytes chunk GCM tag
        - N bytes chunk ciphertext
        
    Returns:
        Total plaintext bytes encrypted.
    """
    if len(key) != AES_KEY_SIZE_BYTES:
        raise ValueError(f"Key must be {AES_KEY_SIZE_BYTES} bytes.")

    base_nonce = generate_secure_bytes(GCM_NONCE_SIZE_BYTES)
    aesgcm = AESGCM(key)

    # Write Header
    out_stream.write(STREAM_HEADER_MAGIC)
    out_stream.write(base_nonce)
    out_stream.write(struct.pack(">I", chunk_size))

    chunk_index = 0
    total_bytes = 0

    curr_chunk = in_stream.read(chunk_size)
    if not curr_chunk:
        # Empty stream (0 bytes): write a single final chunk with 0 bytes
        chunk_nonce = _derive_chunk_nonce(base_nonce, 0)
        chunk_aad = (associated_data or b"") + struct.pack(">IB", 0, 1)
        ct_with_tag = aesgcm.encrypt(chunk_nonce, b"", chunk_aad)
        ciphertext = ct_with_tag[:-GCM_TAG_SIZE_BYTES]
        tag = ct_with_tag[-GCM_TAG_SIZE_BYTES:]
        out_stream.write(struct.pack(">IB", len(ciphertext), 1))
        out_stream.write(tag)
        out_stream.write(ciphertext)
        return 0

    while curr_chunk:
        total_bytes += len(curr_chunk)
        next_chunk = in_stream.read(chunk_size)
        is_final = len(next_chunk) == 0

        chunk_nonce = _derive_chunk_nonce(base_nonce, chunk_index)
        chunk_aad = (associated_data or b"") + struct.pack(">IB", chunk_index, 1 if is_final else 0)

        ct_with_tag = aesgcm.encrypt(chunk_nonce, curr_chunk, chunk_aad)
        ciphertext = ct_with_tag[:-GCM_TAG_SIZE_BYTES]
        tag = ct_with_tag[-GCM_TAG_SIZE_BYTES:]

        out_stream.write(struct.pack(">IB", len(ciphertext), 1 if is_final else 0))
        out_stream.write(tag)
        out_stream.write(ciphertext)

        chunk_index += 1
        curr_chunk = next_chunk

    return total_bytes


def decrypt_stream(
    in_stream: BinaryIO,
    out_stream: BinaryIO,
    key: bytes,
    associated_data: Optional[bytes] = None,
) -> int:
    """
    Streams and decrypts chunked AES-256-GCM ciphertext back into plaintext.
    Verifies authentication tags for every individual chunk before writing to disk.
    
    Returns:
        Total plaintext bytes decrypted.
        
    Raises:
        InvalidCiphertextError: If stream header or chunk boundary is corrupted.
        DecryptionIntegrityError: If any chunk authentication tag check fails.
    """
    if len(key) != AES_KEY_SIZE_BYTES:
        raise ValueError(f"Key must be {AES_KEY_SIZE_BYTES} bytes.")

    aesgcm = AESGCM(key)

    # Read and verify header
    magic = in_stream.read(len(STREAM_HEADER_MAGIC))
    if magic != STREAM_HEADER_MAGIC:
        raise InvalidCiphertextError("Invalid or corrupted stream header magic.")

    base_nonce = in_stream.read(GCM_NONCE_SIZE_BYTES)
    if len(base_nonce) != GCM_NONCE_SIZE_BYTES:
        raise InvalidCiphertextError("Truncated stream header: missing base nonce.")

    chunk_size_bytes = in_stream.read(4)
    if len(chunk_size_bytes) != 4:
        raise InvalidCiphertextError("Truncated stream header: missing chunk size.")

    chunk_index = 0
    total_bytes = 0

    while True:
        chunk_header = in_stream.read(5)  # 4 bytes len + 1 byte is_final
        if not chunk_header:
            raise InvalidCiphertextError("Stream ended unexpectedly before final chunk marker.")

        ct_len, is_final = struct.unpack(">IB", chunk_header)
        tag = in_stream.read(GCM_TAG_SIZE_BYTES)
        if len(tag) != GCM_TAG_SIZE_BYTES:
            raise InvalidCiphertextError("Truncated chunk authentication tag.")

        ciphertext = in_stream.read(ct_len)
        if len(ciphertext) != ct_len:
            raise InvalidCiphertextError("Truncated chunk ciphertext payload.")

        chunk_nonce = _derive_chunk_nonce(base_nonce, chunk_index)
        chunk_aad = (associated_data or b"") + struct.pack(">IB", chunk_index, is_final)

        try:
            plaintext = aesgcm.decrypt(chunk_nonce, ciphertext + tag, chunk_aad)
        except Exception as exc:
            raise DecryptionIntegrityError(
                f"Decryption integrity verification failed on chunk index {chunk_index}."
            ) from exc

        out_stream.write(plaintext)
        total_bytes += len(plaintext)
        chunk_index += 1

        if is_final == 1:
            break

    return total_bytes
