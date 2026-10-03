# HIDE — Encrypted Local Vault CLI

> **Security at its core.** A zero-knowledge local encrypted vault CLI platform for Windows that protects confidential folders and files with authenticated AES-256-GCM encryption and Argon2id key derivation.

## Key Features

- **Authenticated Zero-Knowledge Encryption**: AES-256-GCM AEAD encryption. Data and metadata cannot be read or tampered with without the master key.
- **Argon2id Key Derivation**: Memory-hard KDF resistant against GPU and ASIC cracking attacks.
- **Crash Recovery & Invariant Preservation**: Transactional state machine prevents data loss during sudden power loss or process termination. Source files are only removed after verified encryption.
- **In-Place Folder Encryption**: Run `hide .` inside any directory to pack and encrypt it.
- **Secure Temporary Workspace**: Decrypts into an isolated staging directory; re-encrypts changes and wipes the staging workspace on `hide close`.
- **Emergency Lockdown**: `hide panic` instantly unmounts and wipes all open workspaces across your workstation.

## Architecture

See [docs/implementation_plan.md](docs/implementation_plan.md) and [docs/hide.md](docs/hide.md) for full architectural specifications.
