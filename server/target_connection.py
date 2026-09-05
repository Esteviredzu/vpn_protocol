from __future__ import annotations

import asyncio


class TargetConnection:
    """Соединение сервера с адресом"""

    def __init__(self, hostname: str, port: int) -> None:
        """Сохраняет адрес и порт target"""
        self.hostname = hostname
        self.port = port

        self.reader = None
        self.writer = None

    async def connect(self) -> None:
        """Подключается к указанному адресу"""
        self.reader, self.writer = await asyncio.open_connection(
            self.hostname, self.port
        )

    async def send(self, data: bytes) -> None:
        """Отправляет данные в target"""
        if self.writer is None:
            raise ConnectionError("Target connection is closed")

        self.writer.write(data)

        await self.writer.drain()

    async def receive(self, size: int) -> bytes:
        """Читает данные из target"""
        if self.reader is None:
            raise ConnectionError("Target connection is closed")

        return await self.reader.read(size)

    async def close(self) -> None:
        """Закрывает target"""
        if self.writer is None:
            return

        writer = self.writer
        self.writer = None

        writer.close()

        try:
            await writer.wait_closed()
        except OSError:
            pass
