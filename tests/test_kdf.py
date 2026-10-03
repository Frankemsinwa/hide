"""
Tests for Key Derivation and Credential Management (Phase 3).
"""

import pytest
import base64
from hide.core.kdf import (
    derive_key,
    generate_new_kdf_params,
    create_auth_check_token,
    verify_password_and_derive_key,
    zeroize_buffer,
    EphemeralKey,
    InvalidPasswordError,
    CredentialError,
)
from hide.core.crypto import AES_KEY_SIZE_BYTES


def test_generate_kdf_params():
    params = generate_new_kdf_params()
    assert params.algorithm == "argon2id"
    assert params.memory_cost_kib == 65536
    assert params.time_cost == 3
    assert params.parallelism == 4
    
    salt_bytes = base64.b64decode(params.salt_b64)
    assert len(salt_bytes) == 32


def test_derive_key_deterministic():
    params = generate_new_kdf_params()
    
    key1 = derive_key("MySecretPassword123!", params)
    key2 = derive_key("MySecretPassword123!", params)

    assert len(key1.raw) == AES_KEY_SIZE_BYTES
    assert key1.raw == key2.raw


def test_derive_key_different_salt():
    params1 = generate_new_kdf_params()
    params2 = generate_new_kdf_params()

    key1 = derive_key("SamePassword", params1)
    key2 = derive_key("SamePassword", params2)

    assert key1.raw != key2.raw


def test_ephemeral_key_zeroization():
    raw = b"A" * AES_KEY_SIZE_BYTES
    key = EphemeralKey(raw)
    assert key.raw == raw

    key.zeroize()
    with pytest.raises(CredentialError, match="zeroized"):
        _ = key.raw


def test_ephemeral_key_context_manager():
    raw = b"B" * AES_KEY_SIZE_BYTES
    with EphemeralKey(raw) as key:
        assert key.raw == raw

    with pytest.raises(CredentialError):
        _ = key.raw


def test_auth_check_token_success():
    vault_id = "test-vault-uuid-001"
    params = generate_new_kdf_params()
    password = "CorrectHorseBatteryStaple!"

    with derive_key(password, params) as master_key:
        auth_token = create_auth_check_token(master_key, vault_id)

    # Verify with correct password
    with verify_password_and_derive_key(password, params, auth_token, vault_id) as verified_key:
        assert len(verified_key.raw) == AES_KEY_SIZE_BYTES


def test_auth_check_token_wrong_password():
    vault_id = "test-vault-uuid-002"
    params = generate_new_kdf_params()
    correct_pwd = "ActualVaultPassword999"
    wrong_pwd = "WrongVaultPassword111"

    with derive_key(correct_pwd, params) as master_key:
        auth_token = create_auth_check_token(master_key, vault_id)

    # Attempt unlock with wrong password
    with pytest.raises(InvalidPasswordError):
        verify_password_and_derive_key(wrong_pwd, params, auth_token, vault_id)


def test_auth_check_token_wrong_vault_id():
    params = generate_new_kdf_params()
    password = "MyPassword"

    with derive_key(password, params) as master_key:
        auth_token = create_auth_check_token(master_key, "vault-A")

    # Passphrase is correct, but token bound to vault-A must fail if presented to vault-B
    with pytest.raises(InvalidPasswordError):
        verify_password_and_derive_key(password, params, auth_token, "vault-B")


def test_zeroize_buffer_utility():
    buf = bytearray(b"highly_sensitive_secret_data")
    zeroize_buffer(buf)
    assert all(b == 0 for b in buf)
