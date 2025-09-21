import base64
import os
import time
import threading
from dataclasses import dataclass, field
from typing import Dict


@dataclass
class KeyItem:
    key_id: str
    client_id: str
    peer_id: str
    key_bytes: bytes
    created_at: float = field(default_factory=lambda: time.time())
    consumed: int = 0  # number of bytes consumed
    expires_at: float | None = None
    max_uses: int | None = None
    uses: int = 0


class InMemoryStore:
    def __init__(self) -> None:
        self._keys: Dict[str, KeyItem] = {}
        self._lock = threading.Lock()

    def create_key(self, client_id: str, peer_id: str, length: int, expires_at: float | None = None, max_uses: int | None = None) -> KeyItem:
        with self._lock:
            key_id = base64.urlsafe_b64encode(os.urandom(12)).decode().rstrip('=')
            key_bytes = os.urandom(length)
            item = KeyItem(key_id=key_id, client_id=client_id, peer_id=peer_id, key_bytes=key_bytes, expires_at=expires_at, max_uses=max_uses)
            self._keys[key_id] = item
            return item

    def get_key(self, key_id: str) -> KeyItem | None:
        with self._lock:
            return self._keys.get(key_id)

    def consume(self, key_id: str, nbytes: int) -> tuple[int, bytes]:
        with self._lock:
            item = self._keys.get(key_id)
            if not item:
                raise KeyError("key not found")
            now = time.time()
            if item.expires_at and now > item.expires_at:
                raise ValueError("key expired")
            if item.max_uses is not None and item.uses >= item.max_uses:
                raise ValueError("key usage exceeded")
            start = item.consumed
            end = start + nbytes
            if end > len(item.key_bytes):
                raise ValueError("insufficient key material")
            slice_bytes = item.key_bytes[start:end]
            item.consumed = end
            item.uses += 1
            return start, slice_bytes


store = InMemoryStore()
