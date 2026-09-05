from __future__ import annotations

import asyncio
import secrets
import struct

from protocol.auth import create_server_proof, verify_response
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
from protocol.session import KeyPair, derive_server_session_keys
from protocol.state import ServerState
from server.target_connection import TargetConnection


class ClientConnection:
    def __init__(self, reader, writer, secret: str) -> None:
        self.reader = reader
        self.writer = writer
        self.secret = secret

        self.target = None

        self.key_pair = KeyPair.generate()

        self.cipher = None

        self.state = ServerState.CONNECTED

    async def run(self) -> None:
        await self.handshake()

        await self.open_target()

        await asyncio.gather(self._client_to_target(), self._target_to_client())

    async def handshake(self) -> None:
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
        self._require_state(ServerState.OPEN)

        while True:
            frame = await FrameCodec.read(self.reader, cipher=self.cipher)

            if frame.frame_type == DATA:
                await self.target.send(frame.payload)

            elif frame.frame_type == CLOSE:
                self.state = ServerState.CLOSING
                break

            else:
                raise ValueError(f"Unexpected frame: " f"{frame.frame_type}")

    async def _target_to_client(self) -> None:
        self._require_state(ServerState.OPEN)

        while True:
            data = await self.target.receive(64 * 1024)

            if not data:
                break

            await FrameCodec.send(
                self.writer, FrameCodec.create_data(data), cipher=self.cipher
            )

    @staticmethod
    def _parse_open(payload: bytes) -> tuple[str, int]:
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
        if self.target:
            await self.target.close()

        self.writer.close()

        await self.writer.wait_closed()

        self.state = ServerState.CLOSED

    def _require_state(self, expected: ServerState) -> None:
        if self.state != expected:
            raise RuntimeError(
                f"Invalid server state: "
                f"{self.state.name}, "
                f"expected {expected.name}"
            )
