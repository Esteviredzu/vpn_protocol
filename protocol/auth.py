from __future__ import annotations

import hashlib
import hmac


def _build_transcript(
    challenge: bytes, client_public_key: bytes, server_public_key: bytes
) -> bytes:
    """Собирает данные, которые используются при проверке авторизации"""
    return b"VNPROTO1 AUTH" + challenge + client_public_key + server_public_key


def create_response(
    secret: str, challenge: bytes, client_public_key: bytes, server_public_key: bytes
) -> bytes:
    """Создаёт ответ клиента на challenge сервера"""
    message = _build_transcript(challenge, client_public_key, server_public_key)

    return hmac.new(secret.encode(), message, hashlib.sha256).digest()


def verify_response(
    secret: str,
    challenge: bytes,
    client_public_key: bytes,
    server_public_key: bytes,
    response: bytes,
) -> bool:
    """Проверяет ответ клиента"""
    expected = create_response(secret, challenge, client_public_key, server_public_key)

    return hmac.compare_digest(expected, response)


def create_server_proof(
    secret: str,
    challenge: bytes,
    client_public_key: bytes,
    server_public_key: bytes,
    client_response: bytes,
) -> bytes:
    """Создаёт доказательство того, что сервер тоже знает общий секрет"""
    message = (
        _build_transcript(challenge, client_public_key, server_public_key)
        + client_response
        + b"SERVER"
    )

    return hmac.new(secret.encode(), message, hashlib.sha256).digest()


def verify_server_proof(
    secret: str,
    challenge: bytes,
    client_public_key: bytes,
    server_public_key: bytes,
    client_response: bytes,
    server_proof: bytes,
) -> bool:
    """Проверяет доказательство сервера"""
    expected = create_server_proof(
        secret, challenge, client_public_key, server_public_key, client_response
    )

    return hmac.compare_digest(expected, server_proof)
