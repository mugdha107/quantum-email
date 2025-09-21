# -*- mode: python ; coding: utf-8 -*-

block_cipher = None


a = Analysis(
    ['run_qumail.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=[
        'PyQt5.sip',
        'qumail.app.main',
        'qumail.app.gui.main_window',
        'qumail.app.gui.compose_dialog',
        'qumail.app.gui.settings_dialog',
        'qumail.app.services.config',
        'qumail.app.services.logger',
        'qumail.app.services.km_client',
        'qumail.app.services.email_service',
        'qumail.app.services.crypto_service',
        'qumail.app.services.key_cache',
        'qumail.km_simulator.app',
        'qumail.km_simulator.storage',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)
exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='QuMail',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='QuMail')
