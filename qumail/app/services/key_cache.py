import os
import json
import base64
from typing import Optional
from dataclasses import dataclass

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


@dataclass
class CacheConfig:
    path: str
    password: str


class KeyCache:
    def __init__(self, cfg: CacheConfig):
        self.path = cfg.path
        self.password = cfg.password.encode()
        self._state = {"salt": None, "nonce": None, "blob": None}
        self._mem = {}  # {key_id: base64str}
        self._load()

    def _derive_key(self, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=200_000,
        )
        return kdf.derive(self.password)

    def _load(self):
        if not os.path.exists(self.path):
            return
        try:
            with open(self.path, 'r') as f:
                data = json.load(f)
            salt = base64.b64decode(data["salt"]) if data.get("salt") else None
            nonce = base64.b64decode(data["nonce"]) if data.get("nonce") else None
            blob = base64.b64decode(data["blob"]) if data.get("blob") else None
            if salt and nonce and blob:
                key = self._derive_key(salt)
                aesgcm = AESGCM(key)
                pt = aesgcm.decrypt(nonce, blob, b"qumail-key-cache")
                self._mem = json.loads(pt.decode())
                self._state = {"salt": data["salt"], "nonce": data["nonce"], "blob": data["blob"]}
        except Exception:
            # ignore cache errors
            self._mem = {}

    def _persist(self):
        salt_b = os.urandom(16)
        key = self._derive_key(salt_b)
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        blob = aesgcm.encrypt(nonce, json.dumps(self._mem).encode(), b"qumail-key-cache")
        data = {
            "salt": base64.b64encode(salt_b).decode(),
            "nonce": base64.b64encode(nonce).decode(),
            "blob": base64.b64encode(blob).decode(),
        }
        with open(self.path, 'w') as f:
            json.dump(data, f)
        self._state = data

    def put(self, key_id: str, key_bytes: bytes):
        self._mem[key_id] = base64.b64encode(key_bytes).decode()
        self._persist()

    def get(self, key_id: str) -> Optional[bytes]:
        b64 = self._mem.get(key_id)
        if not b64:
            return None
        try:
            return base64.b64decode(b64)
        except Exception:
            return None
