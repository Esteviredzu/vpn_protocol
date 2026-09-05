from __future__ import annotations

import asyncio
import struct

from protocol.constants import CLOSE, DATA, OPEN
from protocol.framing import FrameCodec
from server.target_connection import TargetConnection


class ClientConnection:
    def __init__(
        self,
        reader,
        writer,
    ) -> None:
        self.reader = reader
        self.writer = writer

        self.target = None

    async def run(self) -> None:
        frame = await FrameCodec.read(
            self.reader,
        )

        if frame.frame_type != OPEN:
            raise ValueError(
                "First frame must be OPEN"
            )

        hostname, port = self._parse_open(
            frame.payload,
        )

        print(
            f"[SERVER] Connecting to "
            f"{hostname}:{port}"
        )

        self.target = TargetConnection(
            hostname,
            port,
        )

        await self.target.connect()

        print(
            f"[SERVER] Connected to "
            f"{hostname}:{port}"
        )

        await asyncio.gather(
            self._client_to_target(),
            self._target_to_client(),
        )

    async def _client_to_target(self) -> None:
        while True:
            frame = await FrameCodec.read(
                self.reader,
            )

            if frame.frame_type == DATA:
                await self.target.send(
                    frame.payload,
                )

            elif frame.frame_type == CLOSE:
                break

            else:
                raise ValueError(
                    f"Unexpected frame: "
                    f"{frame.frame_type}"
                )

    async def _target_to_client(self) -> None:
        while True:
            data = await self.target.receive(
                64 * 1024,
            )

            if not data:
                break

            await FrameCodec.send(
                self.writer,
                FrameCodec.create_data(data),
            )

    @staticmethod
    def _parse_open(
        payload: bytes,
    ) -> tuple[str, int]:
        if len(payload) < 4:
            raise ValueError(
                "Invalid OPEN payload"
            )

        hostname_length = struct.unpack(
            "!H",
            payload[:2],
        )[0]

        hostname_start = 2
        hostname_end = (
            hostname_start + hostname_length
        )

        if len(payload) < hostname_end + 2:
            raise ValueError(
                "Invalid OPEN payload"
            )

        hostname = payload[
            hostname_start:hostname_end
        ].decode()

        port = struct.unpack(
            "!H",
            payload[
                hostname_end:hostname_end + 2
            ],
        )[0]

        return hostname, port

    async def close(self) -> None:
        if self.target:
            await self.target.close()

        self.writer.close()

        await self.writer.wait_closed()
