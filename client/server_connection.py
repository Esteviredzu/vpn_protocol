from __future__ import annotations

import asyncio
import time

from nacl.bindings import crypto_scalarmult

from protocol.auth import create_response, verify_server_proof
from protocol.cipher import SessionCipher, derive_rekeyed_keys
from protocol.constants import (
    AUTH_CHALLENGE,
    AUTH_OK,
    AUTH_RESPONSE,
    CLOSE,
    DATA,
    HELLO,
    HELLO_OK,
    KEEPALIVE_INTERVAL_SECONDS,
    KEEPALIVE_TIMEOUT_SECONDS,
    OPEN,
    OPEN_OK,
    PING,
    PONG,
    REKEY_ACK,
    REKEY_INIT,
    REKEY_INTERVAL_PACKETS,
    REKEY_INTERVAL_SECONDS,
    REKEY_RESP,
    REKEY_TIMEOUT_SECONDS,
)
from protocol.framing import Frame, FrameBatcher, FrameCodec
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

        self.last_activity_time = 0.0
        self.last_rekey_time = 0.0

        self.keepalive_task = None
        self.rekey_task = None

        self.rekey_pending = False
        self.rekey_ephemeral = None

    async def connect(self) -> None:
        """Устанавливает tcp соединение с сервером и запускает handshake"""
        self.reader, self.writer = await asyncio.open_connection(self.host, self.port)

        self.state = ClientState.CONNECTED

        await self.handshake()

        self.last_activity_time = time.monotonic()
        self.last_rekey_time = time.monotonic()

        self.keepalive_task = asyncio.create_task(self._keepalive_loop())
        self.rekey_task = asyncio.create_task(self._rekey_loop())

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
        """Разбивает данные на кадры и отправляет их серверу пакетно"""
        self._require_state(ClientState.OPEN)

        batcher = FrameBatcher(self.writer, self.cipher)

        for frame in FrameCodec.split_data(data):
            await batcher.add(frame)

        await batcher.flush()

        self.last_activity_time = time.monotonic()

    async def read_frame(self):
        """Читает следующий кадр от сервера"""
        self._require_state(ClientState.OPEN)

        frame = await FrameCodec.read(self.reader, cipher=self.cipher)

        self.last_activity_time = time.monotonic()

        if frame.frame_type == PING:
            await FrameCodec.send(
                self.writer, Frame(frame_type=PONG), cipher=self.cipher
            )
            return await self.read_frame()

        if frame.frame_type == PONG:
            return await self.read_frame()

        if frame.frame_type == REKEY_INIT:
            await self._handle_rekey_init(frame.payload)
            return await self.read_frame()

        if frame.frame_type == REKEY_RESP:
            await self._handle_rekey_resp(frame.payload)
            return await self.read_frame()

        if frame.frame_type == REKEY_ACK:
            await self._handle_rekey_ack()
            return await self.read_frame()

        return frame

    async def close(self) -> None:
        """Закрывает соединение с сервером"""
        if self.keepalive_task:
            self.keepalive_task.cancel()
            try:
                await self.keepalive_task
            except asyncio.CancelledError:
                pass
            self.keepalive_task = None

        if self.rekey_task:
            self.rekey_task.cancel()
            try:
                await self.rekey_task
            except asyncio.CancelledError:
                pass
            self.rekey_task = None

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

    async def _keepalive_loop(self) -> None:
        """Отправляет PING для поддержания соединения"""
        try:
            while self.state == ClientState.OPEN:
                await asyncio.sleep(KEEPALIVE_INTERVAL_SECONDS)

                if self.writer is None:
                    break

                now = time.monotonic()
                idle_time = now - self.last_activity_time

                if idle_time >= KEEPALIVE_INTERVAL_SECONDS:
                    await FrameCodec.send(
                        self.writer, Frame(frame_type=PING), cipher=self.cipher
                    )
                    self.last_activity_time = now

                if now - self.last_activity_time > KEEPALIVE_TIMEOUT_SECONDS:
                    raise ConnectionError("Keepalive timeout")

        except asyncio.CancelledError:
            pass
        except Exception as error:
            print(f"[CLIENT] Keepalive error: {error}")
            await self.close()

    async def _rekey_loop(self) -> None:
        """Инициирует rekey при необходимости"""
        try:
            while self.state == ClientState.OPEN:
                await asyncio.sleep(60)

                if self.writer is None or self.cipher is None:
                    break

                now = time.monotonic()
                packets_sent = self.cipher.packets_sent
                time_since_rekey = now - self.last_rekey_time

                needs_rekey = (
                    packets_sent >= REKEY_INTERVAL_PACKETS
                    or time_since_rekey >= REKEY_INTERVAL_SECONDS
                )

                if needs_rekey and not self.rekey_pending:
                    await self._initiate_rekey()

        except asyncio.CancelledError:
            pass
        except Exception as error:
            print(f"[CLIENT] Rekey error: {error}")
            await self.close()

    async def _initiate_rekey(self) -> None:
        """Инициирует rekey"""
        self.rekey_pending = True
        self.rekey_ephemeral = KeyPair.generate()

        await FrameCodec.send(
            self.writer,
            Frame(frame_type=REKEY_INIT, payload=self.rekey_ephemeral.public_key),
            cipher=self.cipher,
        )

        async def timeout_handler():
            await asyncio.sleep(REKEY_TIMEOUT_SECONDS)
            if self.rekey_pending:
                raise ConnectionError("Rekey timeout")

        timeout_task = asyncio.create_task(timeout_handler())

        try:
            while self.rekey_pending:
                frame = await FrameCodec.read(self.reader, cipher=self.cipher)
                if frame.frame_type == REKEY_RESP:
                    await self._handle_rekey_resp(frame.payload)
                    break
        finally:
            timeout_task.cancel()
            try:
                await timeout_task
            except asyncio.CancelledError:
                pass

    async def _handle_rekey_init(self, ephemeral_pubkey: bytes) -> None:
        """Обрабатывает REKEY_INIT от сервера"""
        if len(ephemeral_pubkey) != 32:
            raise ValueError("Invalid rekey public key")

        if self.rekey_pending:
            return

        ephemeral = KeyPair.generate()

        shared_secret = crypto_scalarmult(ephemeral.private_key, ephemeral_pubkey)

        new_send_key, new_receive_key = derive_rekeyed_keys(
            self.cipher.send_key, self.cipher.receive_key, shared_secret
        )

        await FrameCodec.send(
            self.writer,
            Frame(frame_type=REKEY_RESP, payload=ephemeral.public_key),
            cipher=self.cipher,
        )

        self.cipher.update_send_key(new_send_key)
        self.cipher.update_receive_key(new_receive_key)

        self.last_rekey_time = time.monotonic()

    async def _handle_rekey_resp(self, ephemeral_pubkey: bytes) -> None:
        """Обрабатывает REKEY_RESP от сервера"""
        if not self.rekey_pending or self.rekey_ephemeral is None:
            return

        if len(ephemeral_pubkey) != 32:
            raise ValueError("Invalid rekey public key")

        shared_secret = crypto_scalarmult(
            self.rekey_ephemeral.private_key, ephemeral_pubkey
        )

        new_send_key, new_receive_key = derive_rekeyed_keys(
            self.cipher.send_key, self.cipher.receive_key, shared_secret
        )

        self.cipher.update_send_key(new_send_key)
        self.cipher.update_receive_key(new_receive_key)

        await FrameCodec.send(
            self.writer, Frame(frame_type=REKEY_ACK), cipher=self.cipher
        )

        self.rekey_pending = False
        self.rekey_ephemeral = None
        self.last_rekey_time = time.monotonic()

    async def _handle_rekey_ack(self) -> None:
        """Обрабатывает REKEY_ACK от сервера"""
        pass

    def _require_state(self, expected: ClientState) -> None:
        """Проверяет, что соединение находится в нужном состоянии"""
        if self.state != expected:
            raise RuntimeError(
                f"Invalid client state: "
                f"{self.state.name}, "
                f"expected {expected.name}"
            )
