# -*- mode: python ; coding: utf-8 -*-
import sys
from PyInstaller.utils.hooks import collect_submodules, collect_data_files

block_cipher = None

hidden_imports = [
    'cryptography',
    'cryptography.hazmat.primitives.ciphers.aead',
    'cryptography.hazmat.backends.openssl',
    'argon2',
    'argon2.low_level',
    'rich',
    'rich.console',
    'rich.panel',
    'rich.progress',
    'rich.table',
    'click',
    'pydantic',
    'hide',
    'hide.cli',
    'hide.core.crypto',
    'hide.core.kdf',
    'hide.core.metadata',
    'hide.core.manifest',
    'hide.core.models',
    'hide.core.paths',
    'hide.core.recovery',
    'hide.core.registry',
    'hide.core.vault',
    'hide.core.workspace',
    'hide.core.hardening',
]

hidden_imports += collect_submodules('cryptography')
hidden_imports += collect_submodules('argon2')
hidden_imports += collect_submodules('rich')

datas = collect_data_files('cryptography') + collect_data_files('argon2')

a = Analysis(
    ['src/hide/cli.py'],
    pathex=['src'],
    binaries=[],
    datas=datas,
    hiddenimports=hidden_imports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='hide',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
