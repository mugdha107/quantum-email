import os
import base64
from dataclasses import dataclass
from typing import Literal, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

SecurityLevel = Literal[1, 2, 3, 4]


@dataclass
class CryptoResult:
    algo: str
    ciphertext: bytes
    metadata: dict


def _hkdf_derive(key_material: bytes, length: int = 32, salt: bytes | None = None, info: bytes | None = None) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info or b"qumail-aes-key-derivation",
    )
    return hkdf.derive(key_material)


def encrypt(level: SecurityLevel, plaintext: bytes, qkd_key_material: bytes | None = None) -> CryptoResult:
    if level == 4:
        return CryptoResult(algo="PLAINTEXT", ciphertext=plaintext, metadata={})

    if level == 1:
        if qkd_key_material is None:
            raise ValueError("Level 1 (OTP) requires QKD key material")
        if len(qkd_key_material) < len(plaintext):
            raise ValueError("OTP requires key length >= plaintext length")
        ct = bytes([p ^ k for p, k in zip(plaintext, qkd_key_material[: len(plaintext)])])
        return CryptoResult(algo="OTP", ciphertext=ct, metadata={"otp_bytes": len(plaintext)})

    if level in (2, 3):
        if qkd_key_material is None:
            raise ValueError("Level 2/3 requires QKD key material")
        # Level 2: AES-256-GCM with HKDF from QKD material
        # Level 3: same mechanism for now (placeholder for PQC/hybrid)
        aes_key = _hkdf_derive(qkd_key_material, 32)
        aesgcm = AESGCM(aes_key)
        nonce = os.urandom(12)
        aad = b"qumail-level" + (b"2" if level == 2 else b"3")
        ct = aesgcm.encrypt(nonce, plaintext, aad)
        return CryptoResult(
            algo="AES-256-GCM",
            ciphertext=ct,
            metadata={
                "nonce_b64": base64.b64encode(nonce).decode(),
                "aad": aad.decode(),
            },
        )

    raise ValueError("Unsupported security level")


def decrypt(level: SecurityLevel, ciphertext: bytes, qkd_key_material: bytes | None = None, metadata: dict | None = None) -> bytes:
    metadata = metadata or {}
    if level == 4:
        return ciphertext

    if level == 1:
        if qkd_key_material is None:
            raise ValueError("Level 1 (OTP) requires QKD key material")
        if len(qkd_key_material) < len(ciphertext):
            raise ValueError("OTP requires key length >= ciphertext length")
        pt = bytes([c ^ k for c, k in zip(ciphertext, qkd_key_material[: len(ciphertext)])])
        return pt

    if level in (2, 3):
        if qkd_key_material is None:
            raise ValueError("Level 2/3 requires QKD key material")
        aes_key = _hkdf_derive(qkd_key_material, 32)
        aesgcm = AESGCM(aes_key)
        nonce_b64 = metadata.get("nonce_b64")
        if not nonce_b64:
            raise ValueError("Missing nonce for AES-GCM decryption")
        nonce = base64.b64decode(nonce_b64)
        aad = metadata.get("aad", "").encode()
        pt = aesgcm.decrypt(nonce, ciphertext, aad)
        return pt

    raise ValueError("Unsupported security level")
