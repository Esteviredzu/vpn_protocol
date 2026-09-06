from __future__ import annotations

import random
import struct

from protocol.constants import (
    DATA,
    HEADER_FORMAT,
    MAGIC,
    MAX_FRAME_PAYLOAD_SIZE,
    MAX_FRAME_SIZE,
    MIN_DATA_FRAME_SIZE,
    VERSION,
)

HEADER_SIZE = struct.calcsize(HEADER_FORMAT)


class Frame:
    """Хранит тип кадра и его payload"""

    def __init__(self, frame_type: int, payload: bytes = b"") -> None:
        """Создаёт кадр с указанным типом и данными"""
        self.frame_type = frame_type
        self.payload = payload

    @property
    def length(self) -> int:
        """Возвращает размер payload"""
        return len(self.payload)


class FrameCodec:
    """Кодирует и декодирует кадры для передачи по соединению"""

    @staticmethod
    def encode(frame: Frame) -> bytes:
        """Собирает кадр в байты вместе с заголовком"""
        if frame.length > MAX_FRAME_PAYLOAD_SIZE:
            raise ValueError(f"Payload too large: {frame.length}")

        header = struct.pack(
            HEADER_FORMAT, MAGIC, VERSION, frame.frame_type, frame.length
        )

        return header + frame.payload

    @staticmethod
    async def read(reader, cipher=None) -> Frame:
        """Читает кадр из соединения и при необходимости расшифровывает его"""
        header = await reader.readexactly(HEADER_SIZE)

        magic, version, frame_type, length = struct.unpack(HEADER_FORMAT, header)

        if magic != MAGIC:
            raise ValueError("Invalid magic")

        if version != VERSION:
            raise ValueError(f"Unsupported version: {version}")

        if length > MAX_FRAME_SIZE:
            raise ValueError(f"Frame too large: {length}")

        payload = await reader.readexactly(length)

        if cipher is not None:
            payload = cipher.decrypt(header, payload)

        if len(payload) > MAX_FRAME_PAYLOAD_SIZE:
            raise ValueError(f"Payload too large: {len(payload)}")

        return Frame(frame_type=frame_type, payload=payload)

    @staticmethod
    async def send(writer, frame: Frame, cipher=None) -> None:
        """Отправляет кадр в соединение и при необходимости шифрует его"""
        if cipher is None:
            data = FrameCodec.encode(frame)

        else:
            if frame.length > MAX_FRAME_PAYLOAD_SIZE:
                raise ValueError(f"Payload too large: {frame.length}")

            encrypted_length = frame.length + cipher.overhead

            header = struct.pack(
                HEADER_FORMAT, MAGIC, VERSION, frame.frame_type, encrypted_length
            )

            encrypted_payload = cipher.encrypt(header, frame.payload)

            data = header + encrypted_payload

        writer.write(data)

        await writer.drain()

    @staticmethod
    def create_data(data: bytes) -> Frame:
        """Создаёт data кадр из переданных данных"""
        return Frame(frame_type=DATA, payload=data)

    @staticmethod
    def split_data(
        data: bytes,
        min_size: int = MIN_DATA_FRAME_SIZE,
        max_size: int = MAX_FRAME_PAYLOAD_SIZE,
    ) -> list[Frame]:
        """Разбивает большие данные на несколько кадров случайного размера"""
        frames = []
        offset = 0

        while offset < len(data):
            remaining = len(data) - offset

            if remaining <= max_size:
                size = remaining
            else:
                size = random.randint(min_size, max_size)

            frames.append(FrameCodec.create_data(data[offset : offset + size]))

            offset += size

        return frames
