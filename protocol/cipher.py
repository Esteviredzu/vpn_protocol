from __future__ import annotations

from nacl.exceptions import CryptoError
from nacl.secret import Aead

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

    @property
    def overhead(self) -> int:
        """Возвращает размер накладных расходов шифрования (счётчик + MAC)"""
        return COUNTER_SIZE + Aead.MACBYTES

    def encrypt(self, aad: bytes, payload: bytes) -> bytes:
        """Шифрует данные и возвращает счётчик вместе с шифротекстом"""
        if self.send_counter > MAX_COUNTER:
            raise OverflowError("Send counter exhausted")

        counter = self.send_counter

        counter_bytes = counter.to_bytes(COUNTER_SIZE, "big")

        nonce = counter.to_bytes(self.send_box.NONCE_SIZE, "big")

        ciphertext = self.send_box.encrypt(payload, aad=aad, nonce=nonce).ciphertext

        self.send_counter += 1

        return counter_bytes + ciphertext

    def decrypt(self, aad: bytes, payload: bytes) -> bytes:
        """Проверяет счётчик и расшифровывает данные"""
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

        nonce = counter.to_bytes(self.receive_box.NONCE_SIZE, "big")

        try:
            plaintext = self.receive_box.decrypt(ciphertext, aad=aad, nonce=nonce)
        except CryptoError as error:
            raise ValueError("Encrypted frame authentication failed") from error

        self.receive_counter += 1

        return plaintext
