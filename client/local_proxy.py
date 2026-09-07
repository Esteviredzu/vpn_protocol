from __future__ import annotations

import asyncio

from client.server_connection import ServerConnection
from protocol.constants import CLOSE

LOCAL_HOST = "127.0.0.1"
LOCAL_PORT = 9003
MAX_HEADER_SIZE = 64 * 1024


class LocalProxy:
    """Локальный HTTP-прокси, через который приложения подключаются к туннелю"""

    def __init__(self, server_host: str, server_port: int, secret: str) -> None:
        """Сохраняет параметры подключения к VPN-серверу"""
        self.server_host = server_host
        self.server_port = server_port
        self.secret = secret
        self.connection = None

    async def start(self) -> None:
        """Запускает локальный прокси и устанавливает VPN соединение"""
        self.connection = ServerConnection(
            self.server_host, self.server_port, self.secret
        )
        await self.connection.connect()

        server = await asyncio.start_server(self.handle_client, LOCAL_HOST, LOCAL_PORT)
        print(f"[CLIENT] Listening on {LOCAL_HOST}:{LOCAL_PORT}")

        async with server:
            await server.serve_forever()

    async def handle_client(self, local_reader, local_writer) -> None:
        """Обрабатывает одно подключение от локального клиента"""
        stream_id = None
        try:
            request = await self._read_http_headers(local_reader)
            hostname, port = self._parse_connect(request)
            print(f"[CLIENT] CONNECT {hostname}:{port}")

            stream_id = await self.connection.open_stream(hostname, port)
            local_writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await local_writer.drain()

            local_to_server = asyncio.create_task(
                self._local_to_server(local_reader, stream_id)
            )
            server_to_local = asyncio.create_task(
                self._server_to_local(stream_id, local_writer)
            )

            done, pending = await asyncio.wait(
                {local_to_server, server_to_local}, return_when=asyncio.FIRST_COMPLETED
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

        except (ConnectionError, asyncio.IncompleteReadError, ValueError):
            pass
        except Exception as error:
            print(f"[CLIENT] Error: {error}")
        finally:
            if stream_id is not None:
                await self.connection.close_stream(stream_id)
            local_writer.close()
            try:
                await local_writer.wait_closed()
            except OSError:
                pass

    async def _local_to_server(self, local_reader, stream_id: int) -> None:
        """Передаёт данные от локального приложения в vpn"""
        while True:
            data = await local_reader.read(64 * 1024)
            if not data:
                break
            await self.connection.send_data(stream_id, data)

    async def _server_to_local(self, stream_id: int, local_writer) -> None:
        """Передаёт данные от сервера обратно локальному приложению"""
        while True:
            frame = await self.connection.read_frame(stream_id)
            if frame.frame_type == CLOSE:
                break
            elif frame.frame_type == 8:  # DATA
                local_writer.write(frame.payload)
                await local_writer.drain()

    @staticmethod
    async def _read_http_headers(reader) -> bytes:
        """Читает HTTP-заголовки до конца блока CONNECT-запроса"""
        data = bytearray()
        while b"\r\n\r\n" not in data:
            chunk = await reader.read(4096)
            if not chunk:
                raise ConnectionError("Client disconnected")
            data.extend(chunk)
            if len(data) > MAX_HEADER_SIZE:
                raise ValueError("HTTP headers too large")
        return bytes(data)

    @staticmethod
    def _parse_connect(request: bytes) -> tuple[str, int]:
        """Достаёт адрес и порт из HTTP CONNECT-запроса"""
        first_line = request.split(b"\r\n", 1)[0]
        parts = first_line.split()
        if len(parts) != 3:
            raise ValueError("Invalid HTTP request line")
        method, target, _ = parts
        if method != b"CONNECT":
            raise ValueError("Only CONNECT is supported")
        target_str = target.decode()
        if ":" not in target_str:
            raise ValueError("Invalid CONNECT target")
        hostname, port_str = target_str.rsplit(":", 1)
        return hostname, int(port_str)
