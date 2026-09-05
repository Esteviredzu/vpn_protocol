from __future__ import annotations

import hashlib
import hmac


def create_response(secret: str, challenge: bytes) -> bytes:
    return hmac.new(secret.encode(), challenge, hashlib.sha256).digest()


def verify_response(secret: str, challenge: bytes, response: bytes) -> bool:
    expected = create_response(secret, challenge)

    return hmac.compare_digest(expected, response)
