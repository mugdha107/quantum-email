# QuMail: Quantum-Aided Secure Email Client (PyQt + Flask KM Simulator)

QuMail is a Windows-focused email client prototype that integrates a Quantum Key Distribution (QKD) Key Manager (KM) interface to provide enhanced email security. It demonstrates application-layer encryption leveraging quantum-derived keys, while remaining compatible with standard email servers (Gmail, Yahoo, etc.) via SMTP/IMAP.

Core components:
- PyQt GUI desktop client for user interaction.
- Flask-based KM Simulator implementing ETSI GS QKD 014-like REST endpoints for key delivery (for demo/testing).
- Email integration using `smtplib` and `imaplib`.
- Crypto module supporting multiple security levels:
  - Level 1 – Quantum Secure (OTP): One-Time Pad using QKD key material (demo-safe with length checks).
  - Level 2 – Quantum-aided AES: AES-256-GCM where the AES key is derived from QKD key material (HKDF).
  - Level 3 – Extensible option (e.g., PQC placeholder) for future algorithms.
  - Level 4 – No Quantum Security (plaintext).
- Packaged with PyInstaller for Windows.

This project is designed for Smart India Hackathon use cases and future extensibility (e.g., adding chat/audio/video features).

## Architecture
```
qumail/
  app/
    __init__.py
    main.py                 # PyQt application entrypoint
    gui/
      __init__.py
      login_window.py
      main_window.py
      compose_dialog.py
      settings_dialog.py
    services/
      __init__.py
      config.py             # .env and runtime config
      logger.py             # app-wide logging
      km_client.py          # ETSI GS QKD 014-like REST client
      crypto_service.py     # Level 1/2/3/4 encryption/decryption
      email_service.py      # SMTP/IMAP send/receive
    models/
      __init__.py
      message.py            # Simple email message abstraction
  km_simulator/
    app.py                  # Flask server exposing KM-like endpoints
    storage.py              # In-memory key store
  tests/
    test_crypto.py
  .env.example
  requirements.txt
  run_qumail.py
  run_km_simulator.py
  qumail.spec               # PyInstaller spec (basic)
```

## Features
- Login to Email (SMTP/IMAP) and KM service.
- Compose Email with selectable encryption level (1/2/3/4).
- Attach files; encrypt body and attachments at application layer.
- Send via SMTP as standard MIME; includes headers to indicate encryption metadata.
- Receive via IMAP and attempt decryption using KM-derived keys.

## Security Levels
- Level 1 – OTP (One-Time Pad)
  - Uses raw key material from KM.
  - Requires key length ≥ plaintext length; consumes key material once.
  - Demo-focused; not suitable without strict key management.
- Level 2 – AES-GCM (Quantum-aided)
  - HKDF derives 256-bit AES key from KM key material (+ optional salt/context).
  - AES-GCM with random nonce, provides authenticity.
- Level 3 – Placeholder (PQC or other)
  - Hook to integrate post-quantum/hybrid schemes for demo.
  - Currently maps to AES-GCM with independent derivation to showcase pluggability.
- Level 4 – None
  - Plaintext send; useful for baseline testing.

## KM Simulator (Flask)
Implements minimal ETSI GS QKD 014-like REST:
- `POST /api/v1/keys` – Request a new key. Body: `{"client_id":"A","peer_id":"B","length":1024}`. Returns `{key_id, length, key_b64, created_at}`.
- `GET /api/v1/keys/{key_id}` – Retrieve key metadata.
- `POST /api/v1/consume/{key_id}` – Consume N bytes: `{"bytes":N}` → returns `{offset, slice_b64}`; tracks consumption.
- `GET /api/v1/status` – Liveness.

Storage is in-memory for demo. Do NOT use in production.

## Setup
1) Create and activate a virtual environment (recommended).

2) Install dependencies:
```
pip install -r requirements.txt
```

3) Configure environment:
- Copy `.env.example` to `.env` and adjust values.

4) Run the KM Simulator (terminal 1):
```
python run_km_simulator.py
```
It will start on `http://127.0.0.1:5001` by default.

5) Run QuMail client (terminal 2):
```
python run_qumail.py
```

## Email Provider Notes
- Gmail: Enable IMAP in settings. For SMTP/IMAP, use App Passwords if 2FA is enabled. SMTP host: `smtp.gmail.com:587` (STARTTLS), IMAP host: `imap.gmail.com:993` (SSL).
- Yahoo/Outlook: Similar; use provider-specific app passwords and hostnames.

## Packaging with PyInstaller (Windows)
Basic example (from project root):
```
pyinstaller --noconfirm --clean qumail.spec
```
This will produce a `dist/QuMail/QuMail.exe` (one-folder). Customize `qumail.spec` as needed.

## Disclaimer
This is a research/prototype project. The OTP mode requires strict operational controls that are nontrivial in production. The KM Simulator is not a real QKD system. Use responsibly.
