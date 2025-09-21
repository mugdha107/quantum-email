import base64
import os
import time
import threading
import json
from dataclasses import dataclass, field, asdict
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
        self._path: str | None = None

    def create_key(self, client_id: str, peer_id: str, length: int, expires_at: float | None = None, max_uses: int | None = None) -> KeyItem:
        with self._lock:
            key_id = base64.urlsafe_b64encode(os.urandom(12)).decode().rstrip('=')
            key_bytes = os.urandom(length)
            item = KeyItem(key_id=key_id, client_id=client_id, peer_id=peer_id, key_bytes=key_bytes, expires_at=expires_at, max_uses=max_uses)
            self._keys[key_id] = item
            self._autosave()
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
            self._autosave()
            return start, slice_bytes

    # Persistence API
    def set_path(self, path: str):
        with self._lock:
            self._path = path

    def load(self):
        with self._lock:
            if not self._path or not os.path.exists(self._path):
                return
            try:
                with open(self._path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                self._keys.clear()
                for key_id, obj in data.get('keys', {}).items():
                    kb = base64.b64decode(obj['key_b64'])
                    item = KeyItem(
                        key_id=key_id,
                        client_id=obj['client_id'],
                        peer_id=obj['peer_id'],
                        key_bytes=kb,
                        created_at=float(obj.get('created_at', time.time())),
                        consumed=int(obj.get('consumed', 0)),
                        expires_at=obj.get('expires_at'),
                        max_uses=obj.get('max_uses'),
                        uses=int(obj.get('uses', 0)),
                    )
                    self._keys[key_id] = item
            except Exception:
                # best-effort load
                pass

    def save(self):
        with self._lock:
            if not self._path:
                return
            try:
                out = {
                    'keys': {
                        k: {
                            'client_id': v.client_id,
                            'peer_id': v.peer_id,
                            'key_b64': base64.b64encode(v.key_bytes).decode(),
                            'created_at': v.created_at,
                            'consumed': v.consumed,
                            'expires_at': v.expires_at,
                            'max_uses': v.max_uses,
                            'uses': v.uses,
                        }
                        for k, v in self._keys.items()
                    }
                }
                os.makedirs(os.path.dirname(self._path) or '.', exist_ok=True)
                with open(self._path, 'w', encoding='utf-8') as f:
                    json.dump(out, f)
            except Exception:
                # best-effort save
                pass

    def _autosave(self):
        try:
            self.save()
        except Exception:
            pass

store = InMemoryStore()
