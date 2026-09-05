from __future__ import annotations

import struct

from nacl.exceptions import CryptoError
from nacl.secret import Aead

from protocol.constants import HEADER_FORMAT, MAGIC, VERSION

COUNTER_SIZE = 8
MAX_COUNTER = (1 << 64) - 1


class SessionCipher:
    """Отвечает за шифрование и расшифровку данных внутри сессии"""

    def __init__(self, send_key: bytes, receive_key: bytes) -> None:
        """Создаёт шифр с отдельными ключами для отправки и приёма"""
        if len(send_key) != Aead.KEY_SIZE:
            raise ValueError("Invalid send key length")

        if len(receive_key) != Aead.KEY_SIZE:
            raise ValueError("Invalid receive key length")

        self.send_box = Aead(send_key)
        self.receive_box = Aead(receive_key)

        self.send_counter = 0
        self.receive_counter = 0

    def encrypt(self, frame_type: int, payload: bytes) -> bytes:
        """Шифрует данные кадра и добавляет к ним счётчик"""
        if self.send_counter > MAX_COUNTER:
            raise OverflowError("Send counter exhausted")

        counter = self.send_counter

        encrypted_length = COUNTER_SIZE + len(payload) + self.send_box.MACBYTES

        header = struct.pack(
            HEADER_FORMAT, MAGIC, VERSION, frame_type, encrypted_length
        )

        counter_bytes = counter.to_bytes(COUNTER_SIZE, "big")

        nonce = counter.to_bytes(self.send_box.NONCE_SIZE, "big")

        ciphertext = self.send_box.encrypt(payload, aad=header, nonce=nonce).ciphertext

        self.send_counter += 1

        return header + counter_bytes + ciphertext

    def decrypt(self, frame_type: int, payload: bytes) -> bytes:
        """Проверяет и расшифровывает полученные данные"""
        minimum_size = COUNTER_SIZE + self.receive_box.MACBYTES

        if len(payload) < minimum_size:
            raise ValueError("Encrypted frame is too small")

        counter = int.from_bytes(payload[:COUNTER_SIZE], "big")

        if counter != self.receive_counter:
            raise ValueError(
                f"Invalid frame counter: "
                f"got {counter}, "
                f"expected {self.receive_counter}"
            )

        ciphertext = payload[COUNTER_SIZE:]

        header = struct.pack(HEADER_FORMAT, MAGIC, VERSION, frame_type, len(payload))

        nonce = counter.to_bytes(self.receive_box.NONCE_SIZE, "big")

        try:
            plaintext = self.receive_box.decrypt(ciphertext, aad=header, nonce=nonce)
        except CryptoError as error:
            raise ValueError("Encrypted frame authentication failed") from error

        self.receive_counter += 1

        return plaintext
