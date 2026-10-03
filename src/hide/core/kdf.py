"""
Key Derivation Function (KDF) & Credential Management Module for Hide.
Implements Argon2id key derivation according to RFC 9106,
ephemeral secret management with explicit memory zeroization,
fast auth-check token generation, and secure terminal password acquisition.
"""

from __future__ import annotations

import base64
import ctypes
import os
import sys
from typing import Optional, Tuple

from argon2.low_level import hash_secret_raw, Type
from hide.core.crypto import (
    AES_KEY_SIZE_BYTES,
    encrypt_bytes,
    decrypt_bytes,
    generate_secure_bytes,
    DecryptionIntegrityError,
)
from hide.core.models import KdfParameters, AuthCheckToken


# Standard Argon2id parameters
DEFAULT_MEMORY_COST_KIB = 65536  # 64 MiB
DEFAULT_TIME_COST = 3            # 3 iterations
DEFAULT_PARALLELISM = 4          # 4 threads
DEFAULT_SALT_BYTES = 32          # 256-bit salt

# Sentinel plaintext used to generate fast verification auth check token
AUTH_CHECK_SENTINEL = b"HIDE_VAULT_KEY_VERIFICATION_SENTINEL_V1"


class CredentialError(Exception):
    """Base error for key derivation and credential management."""
    pass


class InvalidPasswordError(CredentialError):
    """Raised when password verification fails (bad password)."""
    pass


class PasswordMismatchError(CredentialError):
    """Raised when initial confirmation password does not match."""
    pass


def zeroize_buffer(buf: bytearray) -> None:
    """
    Explicitly overwrites sensitive in-memory byte buffers with zeroes
    using ctypes memset to prevent secrets lingering in process memory.
    """
    if not isinstance(buf, (bytearray, memoryview)):
        return
    try:
        location = (ctypes.c_char * len(buf)).from_buffer(buf)
        ctypes.memset(ctypes.byref(location), 0, len(buf))
    except Exception:
        # Fallback in-place zeroing if buffer interface fails
        for i in range(len(buf)):
            buf[i] = 0


class EphemeralKey:
    """
    Context manager and wrapper holding a 32-byte derived symmetric key.
    Guarantees that the underlying raw key buffer is zeroized upon context exit
    or garbage collection.
    """

    def __init__(self, key_bytes: bytes):
        if len(key_bytes) != AES_KEY_SIZE_BYTES:
            raise ValueError(f"Key must be exactly {AES_KEY_SIZE_BYTES} bytes.")
        self._buffer = bytearray(key_bytes)
        self._is_zeroized = False

    @property
    def raw(self) -> bytes:
        if self._is_zeroized:
            raise CredentialError("Attempted to access zeroized ephemeral key.")
        return bytes(self._buffer)

    def zeroize(self) -> None:
        if not self._is_zeroized:
            zeroize_buffer(self._buffer)
            self._is_zeroized = True

    def __enter__(self) -> "EphemeralKey":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.zeroize()

    def __del__(self) -> None:
        self.zeroize()


def derive_key(
    password: str,
    params: KdfParameters,
) -> EphemeralKey:
    """
    Derives a 256-bit symmetric key from a password and KdfParameters using Argon2id.
    
    Args:
        password: The master password string.
        params: KdfParameters instance containing salt, iterations, memory, and parallelism.
        
    Returns:
        EphemeralKey wrapping the derived 32-byte key.
    """
    if not password:
        raise ValueError("Password cannot be empty.")
    if not params.salt_b64:
        raise ValueError("Salt is missing in KDF parameters.")

    salt = base64.b64decode(params.salt_b64)
    if len(salt) < 16:
        raise ValueError("Salt must be at least 16 bytes.")

    password_bytes = password.encode("utf-8")
    
    raw_key = hash_secret_raw(
        secret=password_bytes,
        salt=salt,
        time_cost=params.time_cost,
        memory_cost=params.memory_cost_kib,
        parallelism=params.parallelism,
        hash_len=params.derived_key_bytes,
        type=Type.ID,  # Argon2id
    )

    return EphemeralKey(raw_key)


def generate_new_kdf_params(
    memory_cost_kib: int = DEFAULT_MEMORY_COST_KIB,
    time_cost: int = DEFAULT_TIME_COST,
    parallelism: int = DEFAULT_PARALLELISM,
) -> KdfParameters:
    """
    Generates fresh KdfParameters with a new cryptographically secure 32-byte salt.
    """
    salt = generate_secure_bytes(DEFAULT_SALT_BYTES)
    salt_b64 = base64.b64encode(salt).decode("ascii")

    return KdfParameters(
        algorithm="argon2id",
        salt_b64=salt_b64,
        memory_cost_kib=memory_cost_kib,
        time_cost=time_cost,
        parallelism=parallelism,
        derived_key_bytes=AES_KEY_SIZE_BYTES,
    )


def create_auth_check_token(key: EphemeralKey, vault_id: str) -> AuthCheckToken:
    """
    Encrypts the AUTH_CHECK_SENTINEL using AES-256-GCM under the derived key.
    The resulting token is saved in vault.meta so future unlock attempts
    can verify password correctness in milliseconds before attempting full unpack.
    """
    aad = f"auth-check:{vault_id}".encode("utf-8")
    nonce, ciphertext, tag = encrypt_bytes(
        plaintext=AUTH_CHECK_SENTINEL,
        key=key.raw,
        associated_data=aad,
    )

    return AuthCheckToken(
        nonce_b64=base64.b64encode(nonce).decode("ascii"),
        ciphertext_b64=base64.b64encode(ciphertext).decode("ascii"),
        tag_b64=base64.b64encode(tag).decode("ascii"),
    )


def verify_password_and_derive_key(
    password: str,
    params: KdfParameters,
    auth_check: AuthCheckToken,
    vault_id: str,
) -> EphemeralKey:
    """
    Derives key from password and verifies it against the vault's AuthCheckToken.
    
    Returns:
        EphemeralKey ready for vault operations if password is valid.
        
    Raises:
        InvalidPasswordError: If password is incorrect.
    """
    ephemeral_key = derive_key(password, params)
    aad = f"auth-check:{vault_id}".encode("utf-8")
    
    try:
        nonce = base64.b64decode(auth_check.nonce_b64)
        ciphertext = base64.b64decode(auth_check.ciphertext_b64)
        tag = base64.b64decode(auth_check.tag_b64)
        
        decrypted = decrypt_bytes(
            nonce=nonce,
            ciphertext=ciphertext,
            tag=tag,
            key=ephemeral_key.raw,
            associated_data=aad,
        )
        if decrypted != AUTH_CHECK_SENTINEL:
            ephemeral_key.zeroize()
            raise InvalidPasswordError("Invalid password: auth token mismatch.")
    except DecryptionIntegrityError:
        ephemeral_key.zeroize()
        raise InvalidPasswordError("Invalid password.")
    except Exception as exc:
        ephemeral_key.zeroize()
        raise InvalidPasswordError("Authentication failed.") from exc

    return ephemeral_key


def prompt_password_with_confirmation(
    prompt: str = "Create vault password: ",
    confirm_prompt: str = "Confirm password: ",
) -> str:
    """
    Prompts for a password twice in the terminal using masked input.
    Ensures passwords match and are non-empty.
    """
    import getpass
    pwd1 = getpass.getpass(prompt)
    if not pwd1:
        raise ValueError("Password cannot be empty.")
    
    pwd2 = getpass.getpass(confirm_prompt)
    if pwd1 != pwd2:
        raise PasswordMismatchError("Passwords do not match.")
    
    return pwd1
