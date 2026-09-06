from __future__ import annotations

import os
import random
import struct

from protocol.constants import (
    DATA,
    HEADER_FORMAT,
    MAGIC,
    MAX_FRAME_PAYLOAD_SIZE,
    MAX_FRAME_SIZE,
    MAX_PADDING_SIZE,
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

        # Безопасное удаление padding только для DATA кадров
        if cipher is not None and frame_type == DATA and len(payload) > 0:
            padding_size = payload[-1]
            if padding_size + 1 > len(payload):
                raise ValueError("Invalid padding size")
            payload = payload[: len(payload) - padding_size - 1]

        return Frame(frame_type=frame_type, payload=payload)

    @staticmethod
    async def send(writer, frame: Frame, cipher=None) -> None:
        """Отправляет кадр в соединение и при необходимости шифрует его"""
        if cipher is None:
            data = FrameCodec.encode(frame)
        else:
            if frame.frame_type == DATA:
                if len(frame.payload) >= MAX_FRAME_PAYLOAD_SIZE:
                    raise ValueError(f"Payload too large: {len(frame.payload)}")

                max_padding = min(
                    MAX_PADDING_SIZE, MAX_FRAME_PAYLOAD_SIZE - len(frame.payload) - 1
                )
                padding_size = random.randint(0, max_padding)

                payload = (
                    frame.payload + os.urandom(padding_size) + bytes([padding_size])
                )
            else:
                payload = frame.payload
                if len(payload) > MAX_FRAME_PAYLOAD_SIZE:
                    raise ValueError(f"Payload too large: {len(payload)}")

            encrypted_length = len(payload) + cipher.overhead

            header = struct.pack(
                HEADER_FORMAT, MAGIC, VERSION, frame.frame_type, encrypted_length
            )

            encrypted_payload = cipher.encrypt(header, payload)

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
        max_size: int = MAX_FRAME_PAYLOAD_SIZE - MAX_PADDING_SIZE - 1,
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
