# -*- mode: python ; coding: utf-8 -*-
# Battle-Hardened AI - Complete EXE Build Specification
# Includes: 21 AI Layers, All JSON files, ML Models, Dashboard, APIs


a = Analysis(
    ['server.py'],
    pathex=['..', '..\\AI'],
    binaries=[],
    datas=[
        # ========== AI MODULES (21 Detection Layers + Support) ==========
        # All 55 Python modules from AI directory
        ('..\\AI\\*.py', 'AI'),
        
        # ========== DASHBOARD UI FILES ==========
        # HTML Templates for web interface
        ('..\\AI\\inspector_ai_monitoring.html', 'AI'),
        ('..\\AI\\docs_portal.html', 'AI'),
        ('..\\AI\\docs_viewer.html', 'AI'),
        ('..\\AI\\swagger_ui.html', 'AI'),
        
        # ========== DATA FILES ==========
        # All 52 JSON configuration and data files (NO relay/ folder)
        ('json', 'json'),
        
        # ========== ML MODELS ==========
        # Pre-trained models and caches
        ('..\\AI\\ml_models', 'AI\\ml_models'),
        
        # ========== SECURITY & CRYPTO ==========
        # Cryptographic keys for secure operations
        ('crypto_keys', 'crypto_keys'),
        
        # Step21 semantic gate policies
        ('..\\policies\\step21', 'policies\\step21'),
        
        # ========== CONFIGURATION ==========
        # Env is provided at runtime via dist/.env.windows; no static template bundled.
        
        # ========== WINDOWS-SPECIFIC ==========
        # Windows Firewall integration scripts
        ('windows-firewall', 'windows-firewall'),
        
        # Installation utilities
        ('installation', 'installation'),
        
        # Windows packaging files
        ('packaging\\windows', 'packaging\\windows'),
    ],
    hiddenimports=[
        # Flask web framework
        'flask',
        'flask_cors',
        # Env loader so .env/.env.windows are honored in the EXE
        'dotenv',
        
        # Security & Cryptography
        'cryptography',
        'cryptography.fernet',
        'cryptography.hazmat.primitives',
        'cryptography.hazmat.backends',
        
        # Network analysis & WebSockets
        'scapy',
        'scapy.all',
        'websockets',
        'websockets.client',
        
        # System monitoring
        'psutil',
        
        # Machine Learning
        'sklearn',
        'sklearn.ensemble',
        'sklearn.preprocessing',
        'sklearn.cluster',
        'joblib',
        
        # Data processing
        'numpy',
        'pandas',
        
        # Additional Flask dependencies
        'werkzeug',
        'jinja2',
        'click',
        'itsdangerous',
        
        # Date/Time
        'datetime',
        'pytz',
        
        # Networking
        'socket',
        'ssl',
        'http',
        'urllib',
        'requests',
        
        # Relay & async
        'asyncio',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        # Exclude relay folder (not for customers)
        'relay',
        'relay.*',
    ],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='BattleHardenedAI',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='..\\assets\\desktop.ico',
)
