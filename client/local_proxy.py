from __future__ import annotations

import asyncio

from client.server_connection import ServerConnection
from protocol.constants import DATA, CLOSE

LOCAL_HOST = "127.0.0.1"
LOCAL_PORT = 8080


class LocalProxy:
    def __init__(self, server_host: str, server_port: int) -> None:
        self.server_host = server_host
        self.server_port = server_port

    async def start(self) -> None:
        server = await asyncio.start_server(self.handle_client, LOCAL_HOST, LOCAL_PORT)

        print(f"[CLIENT] Listening on " f"{LOCAL_HOST}:{LOCAL_PORT}")

        async with server:
            await server.serve_forever()

    async def handle_client(self, local_reader, local_writer) -> None:
        connection = None

        try:
            request = await self._read_http_headers(local_reader)

            hostname, port = self._parse_connect(request)

            print(f"[CLIENT] CONNECT " f"{hostname}:{port}")

            connection = ServerConnection(self.server_host, self.server_port)

            await connection.connect()

            await connection.open_target(hostname, port)

            local_writer.write(b"HTTP/1.1 200 Connection Established\r\n" b"\r\n")

            await local_writer.drain()

            await asyncio.gather(
                self._local_to_server(local_reader, connection),
                self._server_to_local(connection, local_writer),
            )

        except Exception as error:
            print(f"[CLIENT] Error: {error}")

        finally:
            if connection:
                await connection.close()

            local_writer.close()

            await local_writer.wait_closed()

    async def _local_to_server(
        self, local_reader, connection: ServerConnection
    ) -> None:
        while True:
            data = await local_reader.read(64 * 1024)

            if not data:
                break

            await connection.send_data(data)

    async def _server_to_local(
        self, connection: ServerConnection, local_writer
    ) -> None:
        while True:
            frame = await connection.read_frame()

            if frame.frame_type == DATA:
                local_writer.write(frame.payload)

                await local_writer.drain()

            elif frame.frame_type == CLOSE:
                break

            else:
                raise ValueError(f"Unexpected frame: " f"{frame.frame_type}")

    @staticmethod
    async def _read_http_headers(reader) -> bytes:
        data = bytearray()

        while b"\r\n\r\n" not in data:
            chunk = await reader.read(4096)

            if not chunk:
                raise ConnectionError("Client disconnected")

            data.extend(chunk)

        return bytes(data)

    @staticmethod
    def _parse_connect(request: bytes) -> tuple[str, int]:
        first_line = request.split(b"\r\n", 1)[0]

        method, target, _ = first_line.split()

        if method != b"CONNECT":
            raise ValueError("Only CONNECT is supported")

        hostname, port = target.decode().rsplit(":", 1)

        return hostname, int(port)
