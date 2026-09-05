import asyncio
import os

from dotenv import load_dotenv

from client.local_proxy import LocalProxy

load_dotenv()

SERVER_HOST = os.environ["VPN_SERVER_HOST"]

SERVER_PORT = int(os.environ["VPN_SERVER_PORT"])

VPN_SECRET = os.environ["VPN_SECRET"]


async def main() -> None:
    """Запускает локальный vpn proxy"""
    proxy = LocalProxy(SERVER_HOST, SERVER_PORT, VPN_SECRET)

    await proxy.start()


if __name__ == "__main__":
    asyncio.run(main())
