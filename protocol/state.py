from __future__ import annotations

from enum import Enum, auto


class ClientState(Enum):
    DISCONNECTED = auto()
    CONNECTED = auto()
    HELLO_SENT = auto()
    AUTHENTICATING = auto()
    READY = auto()
    OPEN_SENT = auto()
    OPEN = auto()
    CLOSING = auto()
    CLOSED = auto()


class ServerState(Enum):
    CONNECTED = auto()
    HELLO_RECEIVED = auto()
    AUTHENTICATING = auto()
    READY = auto()
    OPEN_RECEIVED = auto()
    OPEN = auto()
    CLOSING = auto()
    CLOSED = auto()
