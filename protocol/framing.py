from __future__ import annotations

import struct

from protocol.constants import DATA, HEADER_FORMAT, MAGIC, MAX_FRAME_SIZE, VERSION

HEADER_SIZE = struct.calcsize(HEADER_FORMAT)


class Frame:
    def __init__(self, frame_type: int, payload: bytes = b"") -> None:
        self.frame_type = frame_type
        self.payload = payload

    @property
    def length(self) -> int:
        return len(self.payload)


class FrameCodec:
    @staticmethod
    def encode(frame: Frame) -> bytes:
        header = struct.pack(
            HEADER_FORMAT, MAGIC, VERSION, frame.frame_type, frame.length
        )

        return header + frame.payload

    @staticmethod
    async def read(reader) -> Frame:
        header = await reader.readexactly(HEADER_SIZE)

        magic, version, frame_type, length = struct.unpack(HEADER_FORMAT, header)

        if magic != MAGIC:
            raise ValueError("Invalid magic")

        if version != VERSION:
            raise ValueError(f"Unsupported version: {version}")

        if length > MAX_FRAME_SIZE:
            raise ValueError(f"Frame too large: {length}")

        payload = await reader.readexactly(length)

        return Frame(frame_type=frame_type, payload=payload)

    @staticmethod
    async def send(writer, frame: Frame) -> None:
        writer.write(FrameCodec.encode(frame))

        await writer.drain()

    @staticmethod
    def create_data(data: bytes) -> Frame:
        return Frame(frame_type=DATA, payload=data)

    @staticmethod
    def split_data(data: bytes, min_size: int, max_size: int) -> list[Frame]:
        import random

        frames = []
        offset = 0

        while offset < len(data):
            remaining = len(data) - offset

            if remaining <= max_size:
                size = remaining
            else:
                size = random.randint(min_size, max_size)

            chunk = data[offset : offset + size]

            frames.append(Frame(frame_type=DATA, payload=chunk))

            offset += size

        return frames
