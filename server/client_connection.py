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
    CLOSE_ACK,
    CLOSE_ACK_TIMEOUT_SECONDS,
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

        self.key_pair = KeyPair.generate()
        self.cipher = None
        self.state = ServerState.CONNECTED

        self.last_activity_time = 0.0
        self.last_rekey_time = 0.0

        self.keepalive_task = None
        self.rekey_task = None
        self.read_task = None

        self.rekey_pending = False
        self.rekey_ephemeral = None
        self.close_ack_received = False

        self.streams: dict[int, TargetConnection] = {}
        self.stream_tasks: dict[int, asyncio.Task] = {}

    async def run(self) -> None:
        """Запускает handshake и центральный цикл чтения"""
        await self.handshake()

        self.last_activity_time = time.monotonic()
        self.last_rekey_time = time.monotonic()

        self.keepalive_task = asyncio.create_task(self._keepalive_loop())
        self.rekey_task = asyncio.create_task(self._rekey_loop())
        self.read_task = asyncio.create_task(self._read_loop())

        try:
            await self.read_task
        except asyncio.CancelledError:
            pass
        finally:
            await self.close()

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

    async def _read_loop(self) -> None:
        """Центральный цикл чтения, маршрутизирующий кадры по стримам"""
        try:
            while self.state not in (ServerState.CLOSING, ServerState.CLOSED):
                frame = await FrameCodec.read(self.reader, cipher=self.cipher)
                self.last_activity_time = time.monotonic()

                if frame.stream_id == 0:
                    await self._handle_control_frame(frame)
                else:
                    await self._handle_stream_frame(frame)
        except asyncio.CancelledError:
            pass
        except Exception as error:
            print(f"[SERVER] Read loop error: {error}")

    async def _handle_control_frame(self, frame: Frame) -> None:
        """Обрабатывает управляющие кадры (stream_id == 0)"""
        if frame.frame_type == PING:
            await FrameCodec.send(
                self.writer, Frame(frame_type=PONG, stream_id=0), cipher=self.cipher
            )
        elif frame.frame_type == REKEY_INIT:
            await self._handle_rekey_init(frame.payload)
        elif frame.frame_type == REKEY_RESP:
            await self._handle_rekey_resp(frame.payload)
        elif frame.frame_type == REKEY_ACK:
            await self._handle_rekey_ack()
        elif frame.frame_type == CLOSE:
            await FrameCodec.send(
                self.writer,
                Frame(frame_type=CLOSE_ACK, stream_id=0),
                cipher=self.cipher,
            )
            self.state = ServerState.CLOSING
        elif frame.frame_type == CLOSE_ACK:
            self.close_ack_received = True

    async def _handle_stream_frame(self, frame: Frame) -> None:
        """Маршрутизирует кадры стрима"""
        if frame.frame_type == OPEN:
            await self._handle_open(frame)
        elif frame.frame_type == DATA:
            if frame.stream_id in self.streams:
                await self.streams[frame.stream_id].send(frame.payload)
        elif frame.frame_type == CLOSE:
            await self._close_stream(frame.stream_id)
            await FrameCodec.send(
                self.writer,
                Frame(frame_type=CLOSE_ACK, stream_id=frame.stream_id),
                cipher=self.cipher,
            )

    async def _handle_open(self, frame: Frame) -> None:
        """Обрабатывает запрос на открытие нового стрима"""
        if frame.stream_id in self.streams:
            return

        payload = frame.payload
        if len(payload) < 6:
            return

        hostname_length = struct.unpack("!H", payload[:2])[0]
        hostname = payload[2 : 2 + hostname_length].decode()
        port = struct.unpack("!H", payload[2 + hostname_length : 4 + hostname_length])[
            0
        ]

        print(f"[SERVER] Stream {frame.stream_id} connecting to {hostname}:{port}")
        target = TargetConnection(hostname, port)
        await target.connect()
        print(f"[SERVER] Stream {frame.stream_id} connected to {hostname}:{port}")

        self.streams[frame.stream_id] = target
        self.stream_tasks[frame.stream_id] = asyncio.create_task(
            self._stream_to_client(frame.stream_id, target)
        )

        await FrameCodec.send(
            self.writer,
            Frame(frame_type=OPEN_OK, stream_id=frame.stream_id),
            cipher=self.cipher,
        )

    async def _stream_to_client(self, stream_id: int, target: TargetConnection) -> None:
        """Читает данные из target и отправляет их клиенту в рамках стрима"""
        batcher = FrameBatcher(self.writer, self.cipher)
        try:
            while True:
                data = await target.receive(64 * 1024)
                if not data:
                    break
                for frame in FrameCodec.split_data(data, stream_id=stream_id):
                    await batcher.add(frame)
                await batcher.flush()
                self.last_activity_time = time.monotonic()
        except Exception:
            pass
        finally:
            await self._close_stream(stream_id)

    async def _close_stream(self, stream_id: int) -> None:
        """Закрывает и очищает ресурсы стрима"""
        if stream_id in self.streams:
            await self.streams[stream_id].close()
            del self.streams[stream_id]
        if stream_id in self.stream_tasks:
            self.stream_tasks[stream_id].cancel()
            del self.stream_tasks[stream_id]

    async def close(self) -> None:
        """Закрывает все стримы и соединение с клиентом"""
        if self.keepalive_task:
            self.keepalive_task.cancel()
        if self.rekey_task:
            self.rekey_task.cancel()
        if self.read_task:
            self.read_task.cancel()

        for stream_id in list(self.streams.keys()):
            await self._close_stream(stream_id)

        if self.writer is None:
            self.state = ServerState.CLOSED
            return

        writer = self.writer
        self.writer = None

        if self.cipher is not None and self.state not in (
            ServerState.CLOSING,
            ServerState.CLOSED,
        ):
            self.state = ServerState.CLOSING
            try:
                await FrameCodec.send(
                    writer, Frame(frame_type=CLOSE, stream_id=0), cipher=self.cipher
                )
                await self._wait_close_ack()
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                pass

        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass
        self.state = ServerState.CLOSED

    async def _wait_close_ack(self) -> None:
        """Ожидает получение CLOSE_ACK от клиента"""
        try:
            async with asyncio.timeout(CLOSE_ACK_TIMEOUT_SECONDS):
                while not self.close_ack_received:
                    frame = await FrameCodec.read(self.reader, cipher=self.cipher)
                    if frame.frame_type == CLOSE_ACK:
                        self.close_ack_received = True
                        break
        except (
            asyncio.TimeoutError,
            asyncio.IncompleteReadError,
            ConnectionError,
            OSError,
            Exception,
        ):
            pass

    async def _keepalive_loop(self) -> None:
        """Отправляет PING для поддержания соединения"""
        try:
            while self.state == ServerState.READY or (
                self.state == ServerState.OPEN and not self.streams
            ):
                await asyncio.sleep(KEEPALIVE_INTERVAL_SECONDS)
                if self.writer is None:
                    break
                now = time.monotonic()
                if now - self.last_activity_time >= KEEPALIVE_INTERVAL_SECONDS:
                    await FrameCodec.send(
                        self.writer,
                        Frame(frame_type=PING, stream_id=0),
                        cipher=self.cipher,
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
            while self.state not in (ServerState.CLOSING, ServerState.CLOSED):
                await asyncio.sleep(60)
                if self.writer is None or self.cipher is None:
                    break
                now = time.monotonic()
                needs_rekey = (
                    self.cipher.packets_sent >= REKEY_INTERVAL_PACKETS
                    or now - self.last_rekey_time >= REKEY_INTERVAL_SECONDS
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
            Frame(
                frame_type=REKEY_INIT,
                payload=self.rekey_ephemeral.public_key,
                stream_id=0,
            ),
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

    async def _handle_rekey_init(self, ephemeral_pubkey: bytes) -> None:
        """Обрабатывает REKEY_INIT от клиента"""
        if len(ephemeral_pubkey) != 32 or self.rekey_pending:
            return
        ephemeral = KeyPair.generate()
        shared_secret = crypto_scalarmult(ephemeral.private_key, ephemeral_pubkey)
        new_send_key, new_receive_key = derive_rekeyed_keys(
            self.cipher.send_key, self.cipher.receive_key, shared_secret
        )
        await FrameCodec.send(
            self.writer,
            Frame(frame_type=REKEY_RESP, payload=ephemeral.public_key, stream_id=0),
            cipher=self.cipher,
        )
        self.cipher.update_send_key(new_send_key)
        self.cipher.update_receive_key(new_receive_key)
        self.last_rekey_time = time.monotonic()

    async def _handle_rekey_resp(self, ephemeral_pubkey: bytes) -> None:
        """Обрабатывает REKEY_RESP от клиента"""
        if (
            not self.rekey_pending
            or self.rekey_ephemeral is None
            or len(ephemeral_pubkey) != 32
        ):
            return
        shared_secret = crypto_scalarmult(
            self.rekey_ephemeral.private_key, ephemeral_pubkey
        )
        new_send_key, new_receive_key = derive_rekeyed_keys(
            self.cipher.send_key, self.cipher.receive_key, shared_secret
        )
        self.cipher.update_send_key(new_send_key)
        self.cipher.update_receive_key(new_receive_key)
        await FrameCodec.send(
            self.writer, Frame(frame_type=REKEY_ACK, stream_id=0), cipher=self.cipher
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
                f"Invalid server state: {self.state.name}, expected {expected.name}"
            )
