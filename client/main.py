import os

from dotenv import load_dotenv

from client.local_proxy import LocalProxy

load_dotenv()


SERVER_HOST = os.environ["VPN_SERVER_HOST"]
SERVER_PORT = int(os.environ["VPN_SERVER_PORT"])


async def main():
    proxy = LocalProxy(server_host=SERVER_HOST, server_port=SERVER_PORT)

    await proxy.start()


if __name__ == "__main__":
    import asyncio

    asyncio.run(main())
