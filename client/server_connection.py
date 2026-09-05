from __future__ import annotations

import asyncio

from protocol.constants import CLOSE, DATA, OPEN
from protocol.framing import Frame, FrameCodec


class ServerConnection:
    def __init__(
        self,
        host: str,
        port: int,
    ) -> None:
        self.host = host
        self.port = port

        self.reader = None
        self.writer = None

    async def connect(self) -> None:
        self.reader, self.writer = (
            await asyncio.open_connection(
                self.host,
                self.port,
            )
        )

    async def open_target(
        self,
        hostname: str,
        port: int,
    ) -> None:
        payload = self._create_open_payload(
            hostname,
            port,
        )

        await FrameCodec.send(
            self.writer,
            Frame(
                frame_type=OPEN,
                payload=payload,
            ),
        )

    async def send_data(
        self,
        data: bytes,
    ) -> None:
        await FrameCodec.send(
            self.writer,
            Frame(
                frame_type=DATA,
                payload=data,
            ),
        )

    async def read_frame(self) -> Frame:
        return await FrameCodec.read(
            self.reader,
        )

    async def close(self) -> None:
        if self.writer is None:
            return

        try:
            await FrameCodec.send(
                self.writer,
                Frame(
                    frame_type=CLOSE,
                ),
            )
        except Exception:
            pass

        self.writer.close()

        await self.writer.wait_closed()

    @staticmethod
    def _create_open_payload(
        hostname: str,
        port: int,
    ) -> bytes:
        hostname_bytes = hostname.encode()

        return (
            len(hostname_bytes).to_bytes(
                2,
                "big",
            )
            + hostname_bytes
            + port.to_bytes(
                2,
                "big",
            )
        )
