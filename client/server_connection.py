from __future__ import annotations

import asyncio

from protocol.auth import create_response
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
from protocol.state import ClientState

MIN_FRAME_SIZE = 1024
MAX_FRAME_SIZE = 16 * 1024


class ServerConnection:
    def __init__(self, host: str, port: int, secret: str) -> None:
        self.host = host
        self.port = port
        self.secret = secret

        self.reader = None
        self.writer = None

        self.state = ClientState.DISCONNECTED

    async def connect(self) -> None:
        self.reader, self.writer = await asyncio.open_connection(self.host, self.port)

        self.state = ClientState.CONNECTED

        await self.handshake()

    async def handshake(self) -> None:
        self._require_state(ClientState.CONNECTED)

        await FrameCodec.send(self.writer, Frame(frame_type=HELLO))

        self.state = ClientState.HELLO_SENT

        frame = await FrameCodec.read(self.reader)

        if frame.frame_type != HELLO_OK:
            raise ValueError("Expected HELLO_OK")

        self.state = ClientState.AUTHENTICATING

        frame = await FrameCodec.read(self.reader)

        if frame.frame_type != AUTH_CHALLENGE:
            raise ValueError("Expected AUTH_CHALLENGE")

        if len(frame.payload) != 32:
            raise ValueError("Invalid challenge length")

        response = create_response(self.secret, frame.payload)

        await FrameCodec.send(
            self.writer, Frame(frame_type=AUTH_RESPONSE, payload=response)
        )

        frame = await FrameCodec.read(self.reader)

        if frame.frame_type != AUTH_OK:
            raise PermissionError("Authentication failed")

        self.state = ClientState.READY

    async def open_target(self, hostname: str, port: int) -> None:
        self._require_state(ClientState.READY)

        hostname_bytes = hostname.encode()

        payload = (
            len(hostname_bytes).to_bytes(2, "big")
            + hostname_bytes
            + port.to_bytes(2, "big")
        )

        await FrameCodec.send(self.writer, Frame(frame_type=OPEN, payload=payload))

        self.state = ClientState.OPEN_SENT

        frame = await FrameCodec.read(self.reader)

        if frame.frame_type != OPEN_OK:
            raise ConnectionError("Server failed to open target")

        self.state = ClientState.OPEN

    async def send_data(self, data: bytes) -> None:
        self._require_state(ClientState.OPEN)

        for frame in FrameCodec.split_data(data, MIN_FRAME_SIZE, MAX_FRAME_SIZE):
            await FrameCodec.send(self.writer, frame)

    async def read_frame(self):
        self._require_state(ClientState.OPEN)

        return await FrameCodec.read(self.reader)

    async def close(self) -> None:
        if self.writer is None:
            return

        if self.state not in (ClientState.CLOSING, ClientState.CLOSED):
            self.state = ClientState.CLOSING

            try:
                await FrameCodec.send(self.writer, Frame(frame_type=CLOSE))
            except Exception:
                pass

        self.writer.close()

        await self.writer.wait_closed()

        self.state = ClientState.CLOSED

    def _require_state(self, expected: ClientState) -> None:
        if self.state != expected:
            raise RuntimeError(
                f"Invalid client state: "
                f"{self.state.name}, "
                f"expected {expected.name}"
            )
