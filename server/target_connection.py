from __future__ import annotations

import asyncio


class TargetConnection:
    def __init__(self, hostname: str, port: int) -> None:
        self.hostname = hostname
        self.port = port

        self.reader = None
        self.writer = None

    async def connect(self) -> None:
        self.reader, self.writer = await asyncio.open_connection(
            self.hostname, self.port
        )

    async def send(self, data: bytes) -> None:
        self.writer.write(data)

        await self.writer.drain()

    async def receive(self, size: int) -> bytes:
        return await self.reader.read(size)

    async def close(self) -> None:
        if self.writer is None:
            return

        self.writer.close()

        await self.writer.wait_closed()
