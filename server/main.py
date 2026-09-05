import asyncio
import os

from dotenv import load_dotenv

from server.client_connection import ClientConnection

load_dotenv()

HOST = "0.0.0.0"
PORT = int(os.getenv("VPN_SERVER_PORT", "9000"))

VPN_SECRET = os.environ["VPN_SECRET"]


async def handle_client(reader, writer) -> None:
    address = writer.get_extra_info("peername")

    print(f"[SERVER] Client connected: " f"{address}")

    connection = ClientConnection(reader, writer, VPN_SECRET)

    try:
        await connection.run()

    except Exception as error:
        print(f"[SERVER] Error for " f"{address}: {error}")

    finally:
        await connection.close()

        print(f"[SERVER] Connection closed: " f"{address}")


async def main() -> None:
    server = await asyncio.start_server(handle_client, HOST, PORT)

    print(f"[SERVER] Listening on " f"{HOST}:{PORT}")

    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
