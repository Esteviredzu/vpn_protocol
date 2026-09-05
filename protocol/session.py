from __future__ import annotations

from dataclasses import dataclass

from nacl.bindings import (
    crypto_kx_client_session_keys,
    crypto_kx_keypair,
    crypto_kx_server_session_keys,
)

KEY_SIZE = 32


@dataclass
class KeyPair:
    """Хранит публичный и приватный ключи стороны"""

    public_key: bytes
    private_key: bytes

    @classmethod
    def generate(cls) -> KeyPair:
        """Генерирует новую пару ключей"""
        public_key, private_key = crypto_kx_keypair()

        return cls(public_key=public_key, private_key=private_key)


@dataclass
class SessionKeys:
    """Хранит ключи для отправки и получения данных"""

    send_key: bytes
    receive_key: bytes


def derive_client_session_keys(
    key_pair: KeyPair, server_public_key: bytes
) -> SessionKeys:
    """Получает ключи сессии для клиента на основе ключей сервера"""
    if len(server_public_key) != KEY_SIZE:
        raise ValueError("Invalid server public key length")

    receive_key, send_key = crypto_kx_client_session_keys(
        key_pair.public_key, key_pair.private_key, server_public_key
    )

    return SessionKeys(send_key=send_key, receive_key=receive_key)


def derive_server_session_keys(
    key_pair: KeyPair, client_public_key: bytes
) -> SessionKeys:
    """Получает ключи сессии для сервера на основе ключей клиента"""
    if len(client_public_key) != KEY_SIZE:
        raise ValueError("Invalid client public key length")

    receive_key, send_key = crypto_kx_server_session_keys(
        key_pair.public_key, key_pair.private_key, client_public_key
    )

    return SessionKeys(send_key=send_key, receive_key=receive_key)
