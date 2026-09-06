from __future__ import annotations

import asyncio
import secrets
import struct
import time

from nacl.bindings import crypto_scalarmult

from protocol.auth import create_server_proof, verify_response
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
    MAX_FRAME_PAYLOAD_SIZE,
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
from protocol.framing import Frame, FrameCodec
from protocol.session import KeyPair, derive_server_session_keys
from protocol.state import ServerState
from server.target_connection import TargetConnection


class ClientConnection:
    """Управляет соединением клиента с сервером"""

    def __init__(self, reader, writer, secret: str) -> None:
        """Сохраняет соединение и создаёт ключи сервера"""
        self.reader = reader
        self.writer = writer
        self.secret = secret

        self.target = None

        self.key_pair = KeyPair.generate()

        self.cipher = None

        self.state = ServerState.CONNECTED

        self.last_activity_time = 0.0
        self.last_rekey_time = 0.0

        self.keepalive_task = None
        self.rekey_task = None

        self.rekey_pending = False
        self.rekey_ephemeral = None

    async def run(self) -> None:
        """Запускает handshake, подключение к target и передачу данных"""
        await self.handshake()

        await self.open_target()

        self.last_activity_time = time.monotonic()
        self.last_rekey_time = time.monotonic()

        self.keepalive_task = asyncio.create_task(self._keepalive_loop())
        self.rekey_task = asyncio.create_task(self._rekey_loop())

        client_to_target = asyncio.create_task(self._client_to_target())

        target_to_client = asyncio.create_task(self._target_to_client())

        done, pending = await asyncio.wait(
            {client_to_target, target_to_client}, return_when=asyncio.FIRST_COMPLETED
        )

        for task in pending:
            task.cancel()

        await asyncio.gather(*pending, return_exceptions=True)

        for task in done:
            if task.cancelled():
                continue

            exception = task.exception()

            if exception is not None:
                raise exception

        if target_to_client in done:
            try:
                await FrameCodec.send(
                    self.writer, Frame(frame_type=CLOSE), cipher=self.cipher
                )
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                pass

    async def handshake(self) -> None:
        """Принимает HELLO, проверяет клиента и создаёт ключи сессии"""
        self._require_state(ServerState.CONNECTED)

        frame = await FrameCodec.read(self.reader)

        if frame.frame_type != HELLO:
            raise ValueError("Expected HELLO")

        client_public_key = frame.payload

        if len(client_public_key) != 32:
            raise ValueError("Invalid client public key")

        self.state = ServerState.HELLO_RECEIVED

        await FrameCodec.send(
            self.writer, Frame(frame_type=HELLO_OK, payload=self.key_pair.public_key)
        )

        self.state = ServerState.AUTHENTICATING

        challenge = secrets.token_bytes(32)

        await FrameCodec.send(
            self.writer, Frame(frame_type=AUTH_CHALLENGE, payload=challenge)
        )

        frame = await FrameCodec.read(self.reader)

        if frame.frame_type != AUTH_RESPONSE:
            raise ValueError("Expected AUTH_RESPONSE")

        response = frame.payload

        if len(response) != 32:
            raise ValueError("Invalid authentication response")

        if not verify_response(
            self.secret,
            challenge,
            client_public_key,
            self.key_pair.public_key,
            response,
        ):
            raise PermissionError("Authentication failed")

        session_keys = derive_server_session_keys(self.key_pair, client_public_key)

        self.cipher = SessionCipher(
            send_key=session_keys.send_key, receive_key=session_keys.receive_key
        )

        server_proof = create_server_proof(
            self.secret,
            challenge,
            client_public_key,
            self.key_pair.public_key,
            response,
        )

        await FrameCodec.send(
            self.writer, Frame(frame_type=AUTH_OK, payload=server_proof)
        )

        self.state = ServerState.READY

    async def open_target(self) -> None:
        """Обрабатывает запрос на подключение к целевому адресу"""
        self._require_state(ServerState.READY)

        frame = await FrameCodec.read(self.reader, cipher=self.cipher)

        if frame.frame_type != OPEN:
            raise ValueError("Expected OPEN")

        self.state = ServerState.OPEN_RECEIVED

        hostname, port = self._parse_open(frame.payload)

        print(f"[SERVER] Connecting to " f"{hostname}:{port}")

        self.target = TargetConnection(hostname, port)

        await self.target.connect()

        print(f"[SERVER] Connected to " f"{hostname}:{port}")

        await FrameCodec.send(
            self.writer, Frame(frame_type=OPEN_OK), cipher=self.cipher
        )

        self.state = ServerState.OPEN

    async def _client_to_target(self) -> None:
        """Передаёт расшифрованные данные от клиента в target"""
        self._require_state(ServerState.OPEN)

        while True:
            frame = await FrameCodec.read(self.reader, cipher=self.cipher)

            self.last_activity_time = time.monotonic()

            if frame.frame_type == DATA:
                await self.target.send(frame.payload)

            elif frame.frame_type == CLOSE:
                self.state = ServerState.CLOSING
                break

            elif frame.frame_type == PING:
                await FrameCodec.send(
                    self.writer, Frame(frame_type=PONG), cipher=self.cipher
                )

            elif frame.frame_type == PONG:
                pass

            elif frame.frame_type == REKEY_INIT:
                await self._handle_rekey_init(frame.payload)

            elif frame.frame_type == REKEY_RESP:
                await self._handle_rekey_resp(frame.payload)

            elif frame.frame_type == REKEY_ACK:
                await self._handle_rekey_ack()

            else:
                raise ValueError(f"Unexpected frame: " f"{frame.frame_type}")

    async def _target_to_client(self) -> None:
        """Читает данные от target и отправляет их клиенту"""
        self._require_state(ServerState.OPEN)

        while True:
            data = await self.target.receive(MAX_FRAME_PAYLOAD_SIZE)

            if not data:
                break

            await FrameCodec.send(
                self.writer, FrameCodec.create_data(data), cipher=self.cipher
            )

            self.last_activity_time = time.monotonic()

    @staticmethod
    def _parse_open(payload: bytes) -> tuple[str, int]:
        """Достаёт hostname и port из кaдра"""
        if len(payload) < 4:
            raise ValueError("Invalid OPEN payload")

        hostname_length = struct.unpack("!H", payload[:2])[0]

        hostname_start = 2

        hostname_end = hostname_start + hostname_length

        if len(payload) < hostname_end + 2:
            raise ValueError("Invalid OPEN payload")

        hostname = payload[hostname_start:hostname_end].decode()

        port = struct.unpack("!H", payload[hostname_end : hostname_end + 2])[0]

        return hostname, port

    async def close(self) -> None:
        """Закрывает target и соединение с клиентом"""
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

        if self.target:
            await self.target.close()

        if self.writer is None:
            self.state = ServerState.CLOSED
            return

        writer = self.writer
        self.writer = None

        writer.close()

        try:
            await writer.wait_closed()
        except OSError:
            pass

        self.state = ServerState.CLOSED

    async def _keepalive_loop(self) -> None:
        """Отправляет PING для поддержания соединения"""
        try:
            while self.state == ServerState.OPEN:
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
            print(f"[SERVER] Keepalive error: {error}")
            await self.close()

    async def _rekey_loop(self) -> None:
        """Инициирует rekey при необходимости"""
        try:
            while self.state == ServerState.OPEN:
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
            print(f"[SERVER] Rekey error: {error}")
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
        """Обрабатывает REKEY_INIT от клиента"""
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
        """Обрабатывает REKEY_RESP от клиента"""
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
        """Обрабатывает REKEY_ACK от клиента"""
        pass

    def _require_state(self, expected: ServerState) -> None:
        """Проверяет, что сервер находится в нужном состоянии"""
        if self.state != expected:
            raise RuntimeError(
                f"Invalid server state: "
                f"{self.state.name}, "
                f"expected {expected.name}"
            )
