import base64
import time
from typing import Optional, Tuple
from dataclasses import dataclass

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

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

    def __init__(self, cfg: KMConfig):
        self.cfg = cfg
        self.session = requests.Session()
        # Do not use system proxy vars for localhost
        self.session.trust_env = False
        # Robust retries for transient connection issues
        retry = Retry(total=3, connect=3, read=3, backoff_factor=0.3,
                      status_forcelist=(502, 503, 504))
        adapter = HTTPAdapter(max_retries=retry)
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)
        # Increase timeout to accommodate slower hosts
        self.timeout = 30.0

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
        """Request a new key and verify with HMAC.
        Try GET first to avoid environments where POST stalls; fallback to POST.
        """
        params = {
            "length": int(length or self.cfg.default_key_length),
            "client_id": self.cfg.client_id,
            "peer_id": self.cfg.peer_id,
        }
        data = None
        # Fast attempt via GET with short timeout
        try:
            r = self.session.get(f"{self.cfg.base_url}/api/v1/keys/new", params=params, timeout=5.0)
            r.raise_for_status()
            data = r.json()
        except Exception:
            # Fallback to POST with normal timeout
            try:
                data = self.request_key(length)
            except Exception:
                # Re-raise last error for caller
                raise
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

    def material_with_verify(self, key_id: str, nbytes: int, offset: int = 0) -> Tuple[int, bytes, bool]:
        """Fetch a non-consuming slice of key material and verify integrity.
        Requires KM simulator >= current version supporting /api/v1/material.
        """
        params = {"bytes": int(nbytes), "offset": int(offset)}
        r = self.session.get(f"{self.cfg.base_url}/api/v1/material/{key_id}", params=params, timeout=self.timeout)
        r.raise_for_status()
        data = r.json()
        slice_b = base64.b64decode(data["slice_b64"])
        h = data.get("slice_hmac", "")
        tampered = (self._hmac_hex(slice_b) != h)
        return int(data.get("offset", 0)), slice_b, tampered
