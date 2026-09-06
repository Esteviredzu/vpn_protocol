from __future__ import annotations

import hashlib

from nacl.exceptions import CryptoError
from nacl.secret import Aead

COUNTER_SIZE = 8
MAX_COUNTER = (1 << 64) - 1
REPLAY_WINDOW_SIZE = 1024


class ReplayProtection:
    """Защита от replay-атак с помощью sliding window"""

    def __init__(self, window_size: int = REPLAY_WINDOW_SIZE) -> None:
        """Создаёт sliding window заданного размера"""
        self.window_size = window_size
        self.last_accepted = -1
        self.window = 0

    def check(self, counter: int) -> bool:
        """Проверяет, что counter не был использован ранее"""
        if counter > self.last_accepted:
            shift = counter - self.last_accepted
            if shift >= self.window_size:
                self.window = 1
            else:
                self.window = (self.window << shift) | 1
            self.last_accepted = counter
            return True
        elif counter >= self.last_accepted - self.window_size + 1:
            bit = 1 << (self.last_accepted - counter)
            if self.window & bit:
                return False
            self.window |= bit
            return True
        else:
            return False


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
        self.send_key = send_key
        self.receive_key = receive_key

        self.send_counter = 0
        self.receive_counter = 0

        self.replay = ReplayProtection()

        self.packets_sent = 0
        self.packets_received = 0

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
        self.packets_sent += 1

        return counter_bytes + ciphertext

    def decrypt(self, aad: bytes, payload: bytes) -> bytes:
        """Проверяет счётчик и расшифровывает данные"""
        minimum_size = COUNTER_SIZE + self.receive_box.MACBYTES

        if len(payload) < minimum_size:
            raise ValueError("Encrypted frame is too small")

        counter = int.from_bytes(payload[:COUNTER_SIZE], "big")

        if not self.replay.check(counter):
            raise ValueError(f"Replay detected: counter {counter}")

        ciphertext = payload[COUNTER_SIZE:]

        nonce = counter.to_bytes(self.receive_box.NONCE_SIZE, "big")

        try:
            plaintext = self.receive_box.decrypt(ciphertext, aad=aad, nonce=nonce)
        except CryptoError as error:
            raise ValueError("Encrypted frame authentication failed") from error

        self.packets_received += 1

        return plaintext

    def update_send_key(self, new_key: bytes) -> None:
        """Обновляет ключ отправки и сбрасывает счётчик"""
        if len(new_key) != Aead.KEY_SIZE:
            raise ValueError("Invalid key length")
        self.send_key = new_key
        self.send_box = Aead(new_key)
        self.send_counter = 0
        self.packets_sent = 0

    def update_receive_key(self, new_key: bytes) -> None:
        """Обновляет ключ приёма, сбрасывает счётчик и защиту от replay"""
        if len(new_key) != Aead.KEY_SIZE:
            raise ValueError("Invalid key length")
        self.receive_key = new_key
        self.receive_box = Aead(new_key)
        self.receive_counter = 0
        self.packets_received = 0
        self.replay = ReplayProtection()


def derive_rekeyed_keys(
    old_send_key: bytes, old_receive_key: bytes, shared_secret: bytes
) -> tuple[bytes, bytes]:
    """
    Выводит новые ключи из старых и общего секрета.
    Гарантирует направленную симметрию: новый send_key клиента будет равен
    новому receive_key сервера, и наоборот.
    """
    h_send = hashlib.sha256()
    h_send.update(b"VNPROTO1 REKEY_SEND")
    h_send.update(old_send_key)
    h_send.update(shared_secret)
    new_send_key = h_send.digest()

    h_recv = hashlib.sha256()
    h_recv.update(b"VNPROTO1 REKEY_RECV")
    h_recv.update(old_receive_key)
    h_recv.update(shared_secret)
    new_receive_key = h_recv.digest()

    return new_send_key, new_receive_key
