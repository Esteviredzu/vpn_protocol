from __future__ import annotations

import asyncio
import secrets
import struct

from protocol.auth import verify_response
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
from protocol.state import ServerState
from server.target_connection import TargetConnection


class ClientConnection:
    def __init__(self, reader, writer, secret: str) -> None:
        self.reader = reader
        self.writer = writer
        self.secret = secret

        self.target = None

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

        self.state = ServerState.HELLO_RECEIVED

        await FrameCodec.send(self.writer, Frame(frame_type=HELLO_OK))

        self.state = ServerState.AUTHENTICATING

        challenge = secrets.token_bytes(32)

        await FrameCodec.send(
            self.writer, Frame(frame_type=AUTH_CHALLENGE, payload=challenge)
        )

        frame = await FrameCodec.read(self.reader)

        if frame.frame_type != AUTH_RESPONSE:
            raise ValueError("Expected AUTH_RESPONSE")

        if not verify_response(self.secret, challenge, frame.payload):
            raise PermissionError("Authentication failed")

        await FrameCodec.send(self.writer, Frame(frame_type=AUTH_OK))

        self.state = ServerState.READY

    async def open_target(self) -> None:
        self._require_state(ServerState.READY)

        frame = await FrameCodec.read(self.reader)

        if frame.frame_type != OPEN:
            raise ValueError("Expected OPEN")

        self.state = ServerState.OPEN_RECEIVED

        hostname, port = self._parse_open(frame.payload)

        print(f"[SERVER] Connecting to " f"{hostname}:{port}")

        self.target = TargetConnection(hostname, port)

        await self.target.connect()

        print(f"[SERVER] Connected to " f"{hostname}:{port}")

        await FrameCodec.send(self.writer, Frame(frame_type=OPEN_OK))

        self.state = ServerState.OPEN

    async def _client_to_target(self) -> None:
        self._require_state(ServerState.OPEN)

        while True:
            frame = await FrameCodec.read(self.reader)

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

            await FrameCodec.send(self.writer, FrameCodec.create_data(data))

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
