import base64
import time
from typing import Optional, Tuple

import requests

from .config import KMConfig
import hmac
import hashlib


class KMClient:
    """Client for ETSI GS QKD 014-like REST key delivery APIs.

    Endpoints expected (KM Simulator):
      - POST /api/v1/keys {client_id, peer_id, length}
      - GET  /api/v1/keys/{key_id}
      - POST /api/v1/consume/{key_id} {bytes}
      - GET  /api/v1/status
    """

    def __init__(self, cfg: KMConfig, timeout: float = 10.0):
        self.cfg = cfg
        self.session = requests.Session()
        self.timeout = timeout

    def _hmac_hex(self, data: bytes) -> str:
        return hmac.new(self.cfg.integrity_secret.encode(), data, hashlib.sha256).hexdigest()

    def status(self) -> bool:
        try:
            r = self.session.get(f"{self.cfg.base_url}/api/v1/status", timeout=self.timeout)
            r.raise_for_status()
            return r.json().get("status") == "ok"
        except Exception:
            return False

    def request_key(self, length: Optional[int] = None) -> dict:
        payload = {
            "client_id": self.cfg.client_id,
            "peer_id": self.cfg.peer_id,
            "length": int(length or self.cfg.default_key_length),
        }
        r = self.session.post(f"{self.cfg.base_url}/api/v1/keys", json=payload, timeout=self.timeout)
        r.raise_for_status()
        return r.json()

    def request_key_with_verify(self, length: Optional[int] = None) -> Tuple[str, bytes, bool]:
        data = self.request_key(length)
        key_id = data["key_id"]
        key_b = base64.b64decode(data.get("key_b64", ""))
        h = data.get("key_hmac", "")
        tampered = (self._hmac_hex(key_b) != h)
        return key_id, key_b, tampered

    def get_key(self, key_id: str) -> dict:
        r = self.session.get(f"{self.cfg.base_url}/api/v1/keys/{key_id}", timeout=self.timeout)
        r.raise_for_status()
        return r.json()

    def consume(self, key_id: str, nbytes: int) -> Tuple[int, bytes]:
        r = self.session.post(
            f"{self.cfg.base_url}/api/v1/consume/{key_id}", json={"bytes": int(nbytes)}, timeout=self.timeout
        )
        r.raise_for_status()
        data = r.json()
        slice_b64 = data["slice_b64"]
        offset = int(data["offset"])
        return offset, base64.b64decode(slice_b64)

    def consume_with_verify(self, key_id: str, nbytes: int) -> Tuple[int, bytes, bool]:
        r = self.session.post(
            f"{self.cfg.base_url}/api/v1/consume/{key_id}", json={"bytes": int(nbytes)}, timeout=self.timeout
        )
        r.raise_for_status()
        data = r.json()
        slice_b = base64.b64decode(data["slice_b64"])
        h = data.get("slice_hmac", "")
        tampered = (self._hmac_hex(slice_b) != h)
        return int(data["offset"]), slice_b, tampered
