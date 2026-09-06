from __future__ import annotations

import asyncio

from protocol.auth import create_response, verify_server_proof
from protocol.cipher import SessionCipher
from protocol.constants import (
    AUTH_CHALLENGE,
    AUTH_OK,
    AUTH_RESPONSE,
    CLOSE,
    DATA,
    HELLO,
    HELLO_OK,
    OPEN,
    OPEN_OK,
)
from protocol.framing import Frame, FrameCodec
from protocol.session import KeyPair, derive_client_session_keys
from protocol.state import ClientState


class ServerConnection:
    """Управляет соединением клиента с VPN-сервером"""

    def __init__(self, host: str, port: int, secret: str) -> None:
        """Сохраняет настройки соединения и создаёт ключи клиента"""
        self.host = host
        self.port = port
        self.secret = secret

        self.reader = None
        self.writer = None

        self.key_pair = KeyPair.generate()

        self.cipher = None

        self.state = ClientState.DISCONNECTED

    async def connect(self) -> None:
        """Устанавливает tcp соединение с сервером и запускает handshake"""
        self.reader, self.writer = await asyncio.open_connection(self.host, self.port)

        self.state = ClientState.CONNECTED

        await self.handshake()

    async def handshake(self) -> None:
        """Проводит обмен ключами и авторизацию клиента"""
        self._require_state(ClientState.CONNECTED)

        await FrameCodec.send(
            self.writer, Frame(frame_type=HELLO, payload=self.key_pair.public_key)
        )

        self.state = ClientState.HELLO_SENT

        frame = await FrameCodec.read(self.reader)

        if frame.frame_type != HELLO_OK:
            raise ValueError("Expected HELLO_OK")

        server_public_key = frame.payload

        if len(server_public_key) != 32:
            raise ValueError("Invalid server public key")

        self.state = ClientState.AUTHENTICATING

        frame = await FrameCodec.read(self.reader)

        if frame.frame_type != AUTH_CHALLENGE:
            raise ValueError("Expected AUTH_CHALLENGE")

        challenge = frame.payload

        if len(challenge) != 32:
            raise ValueError("Invalid challenge length")

        response = create_response(
            self.secret, challenge, self.key_pair.public_key, server_public_key
        )

        await FrameCodec.send(
            self.writer, Frame(frame_type=AUTH_RESPONSE, payload=response)
        )

        frame = await FrameCodec.read(self.reader)

        if frame.frame_type != AUTH_OK:
            raise PermissionError("Authentication failed")

        if not verify_server_proof(
            self.secret,
            challenge,
            self.key_pair.public_key,
            server_public_key,
            response,
            frame.payload,
        ):
            raise PermissionError("Server authentication failed")

        session_keys = derive_client_session_keys(self.key_pair, server_public_key)

        self.cipher = SessionCipher(
            send_key=session_keys.send_key, receive_key=session_keys.receive_key
        )

        self.state = ClientState.READY

    async def open_target(self, hostname: str, port: int) -> None:
        """Просит сервер открыть соединение с указанным адресом"""
        self._require_state(ClientState.READY)

        hostname_bytes = hostname.encode()

        payload = (
            len(hostname_bytes).to_bytes(2, "big")
            + hostname_bytes
            + port.to_bytes(2, "big")
        )

        await FrameCodec.send(
            self.writer, Frame(frame_type=OPEN, payload=payload), cipher=self.cipher
        )

        self.state = ClientState.OPEN_SENT

        frame = await FrameCodec.read(self.reader, cipher=self.cipher)

        if frame.frame_type != OPEN_OK:
            raise ConnectionError("Server failed to open target")

        self.state = ClientState.OPEN

    async def send_data(self, data: bytes) -> None:
        """Разбивает данные на кадры и отправляет их серверу"""
        self._require_state(ClientState.OPEN)

        for frame in FrameCodec.split_data(data):
            await FrameCodec.send(self.writer, frame, cipher=self.cipher)

    async def read_frame(self):
        """Читает следующий кадр от сервера"""
        self._require_state(ClientState.OPEN)

        return await FrameCodec.read(self.reader, cipher=self.cipher)

    async def close(self) -> None:
        """Закрывает соединение с сервером"""
        if self.writer is None:
            return

        writer = self.writer
        self.writer = None

        if self.cipher is not None and self.state not in (
            ClientState.CLOSING,
            ClientState.CLOSED,
        ):
            self.state = ClientState.CLOSING

            try:
                await FrameCodec.send(
                    writer, Frame(frame_type=CLOSE), cipher=self.cipher
                )
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                pass

        writer.close()

        try:
            await writer.wait_closed()
        except OSError:
            pass

        self.state = ClientState.CLOSED

    def _require_state(self, expected: ClientState) -> None:
        """Проверяет, что соединение находится в нужном состоянии"""
        if self.state != expected:
            raise RuntimeError(
                f"Invalid client state: "
                f"{self.state.name}, "
                f"expected {expected.name}"
            )
