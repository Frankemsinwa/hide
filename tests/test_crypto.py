"""
Tests for Cryptographic Core Engine (Phase 2).
Covers AES-256-GCM AEAD, streaming encryption, tamper detection, and error conditions.
"""

import os
from io import BytesIO
import pytest
from hide.core.crypto import (
    encrypt_bytes,
    decrypt_bytes,
    encrypt_payload_envelope,
    decrypt_payload_envelope,
    encrypt_stream,
    decrypt_stream,
    generate_secure_bytes,
    DecryptionIntegrityError,
    InvalidCiphertextError,
    AES_KEY_SIZE_BYTES,
    GCM_NONCE_SIZE_BYTES,
    GCM_TAG_SIZE_BYTES,
)


@pytest.fixture
def key_32():
    return generate_secure_bytes(AES_KEY_SIZE_BYTES)


def test_encrypt_decrypt_roundtrip(key_32):
    plaintext = b"Super confidential data that must stay hidden!"
    aad = b"vault-id-uuid-1234"
    
    nonce, ciphertext, tag = encrypt_bytes(plaintext, key_32, associated_data=aad)
    assert len(nonce) == GCM_NONCE_SIZE_BYTES
    assert len(tag) == GCM_TAG_SIZE_BYTES
    assert ciphertext != plaintext

    recovered = decrypt_bytes(nonce, ciphertext, tag, key_32, associated_data=aad)
    assert recovered == plaintext


def test_envelope_roundtrip(key_32):
    plaintext = b"Envelope test payload"
    aad = b"aad-metadata"

    envelope = encrypt_payload_envelope(plaintext, key_32, associated_data=aad)
    recovered = decrypt_payload_envelope(envelope, key_32, associated_data=aad)
    assert recovered == plaintext


def test_reject_wrong_key(key_32):
    plaintext = b"Classified document"
    nonce, ciphertext, tag = encrypt_bytes(plaintext, key_32)

    wrong_key = generate_secure_bytes(AES_KEY_SIZE_BYTES)
    with pytest.raises(DecryptionIntegrityError):
        decrypt_bytes(nonce, ciphertext, tag, wrong_key)


def test_reject_tampered_ciphertext(key_32):
    plaintext = b"Payload before tamper"
    nonce, ciphertext, tag = encrypt_bytes(plaintext, key_32)

    # Flip 1 bit in ciphertext
    tampered_ct = bytearray(ciphertext)
    tampered_ct[0] ^= 0x01

    with pytest.raises(DecryptionIntegrityError):
        decrypt_bytes(nonce, bytes(tampered_ct), tag, key_32)


def test_reject_tampered_tag(key_32):
    plaintext = b"Payload with valid tag"
    nonce, ciphertext, tag = encrypt_bytes(plaintext, key_32)

    # Flip 1 bit in authentication tag
    tampered_tag = bytearray(tag)
    tampered_tag[0] ^= 0xFF

    with pytest.raises(DecryptionIntegrityError):
        decrypt_bytes(nonce, ciphertext, bytes(tampered_tag), key_32)


def test_reject_mismatched_aad(key_32):
    plaintext = b"Bound to specific vault ID"
    nonce, ciphertext, tag = encrypt_bytes(plaintext, key_32, associated_data=b"vault-A")

    with pytest.raises(DecryptionIntegrityError):
        decrypt_bytes(nonce, ciphertext, tag, key_32, associated_data=b"vault-B")


def test_streaming_roundtrip_multi_chunks(key_32):
    # Create 250 KiB of random data (spanning multiple 64 KiB chunks)
    original_data = os.urandom(250 * 1024)
    in_stream = BytesIO(original_data)
    encrypted_stream = BytesIO()
    decrypted_stream = BytesIO()

    aad = b"streaming-test-aad"
    total_enc = encrypt_stream(in_stream, encrypted_stream, key_32, associated_data=aad, chunk_size=64 * 1024)
    assert total_enc == len(original_data)

    encrypted_stream.seek(0)
    total_dec = decrypt_stream(encrypted_stream, decrypted_stream, key_32, associated_data=aad)
    assert total_dec == len(original_data)
    assert decrypted_stream.getvalue() == original_data


def test_streaming_empty_payload(key_32):
    # Empty 0-byte file
    in_stream = BytesIO(b"")
    encrypted_stream = BytesIO()
    decrypted_stream = BytesIO()

    total_enc = encrypt_stream(in_stream, encrypted_stream, key_32)
    assert total_enc == 0

    encrypted_stream.seek(0)
    total_dec = decrypt_stream(encrypted_stream, decrypted_stream, key_32)
    assert total_dec == 0
    assert decrypted_stream.getvalue() == b""


def test_streaming_tamper_detection(key_32):
    original_data = b"Testing stream integrity verification." * 100
    in_stream = BytesIO(original_data)
    encrypted_stream = BytesIO()

    encrypt_stream(in_stream, encrypted_stream, key_32)

    # Tamper with bytes inside the ciphertext of the first chunk
    payload = bytearray(encrypted_stream.getvalue())
    # Offset past header (8 magic + 12 nonce + 4 chunk_size + 4 len + 1 is_final + 16 tag = 45 bytes)
    payload[50] ^= 0x42

    tampered_stream = BytesIO(bytes(payload))
    out_stream = BytesIO()

    with pytest.raises(DecryptionIntegrityError):
        decrypt_stream(tampered_stream, out_stream, key_32)


def test_streaming_invalid_magic(key_32):
    bad_stream = BytesIO(b"CORRUPT_MAGIC_BYTES_1234567890")
    out_stream = BytesIO()

    with pytest.raises(InvalidCiphertextError, match="magic"):
        decrypt_stream(bad_stream, out_stream, key_32)
