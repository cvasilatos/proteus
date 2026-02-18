"""Socket management utilities for Proteus.

This module provides a centralized socket manager to handle socket creation,
connection, reconnection, and cleanup operations.
"""

import logging
import socket
from typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    from decimalog.logger import CustomLogger


class SocketManager:
    """Manages socket connections with automatic reconnection capabilities."""

    def __init__(self, host: str, port: int, timeout: float = 1.0) -> None:
        """Initialize the SocketManager with connection parameters.

        Args:
            host: Target host address
            port: Target port number
            timeout: Socket timeout in seconds
        """
        self.logger: CustomLogger = cast("CustomLogger", logging.getLogger(f"{self.__class__.__module__}.{self.__class__.__name__}"))
        self._host = host
        self._port = port
        self._timeout = timeout
        self._sock: socket.socket | None = None

    def connect(self) -> None:
        """Establish a socket connection to the target server."""
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.settimeout(self._timeout)
        self._sock.connect((self._host, self._port))
        self.logger.debug(f"Connected to {self._host}:{self._port}")

    def reconnect(self) -> None:
        """Close existing connection and establish a new one."""
        self.close()
        self.connect()
        self.logger.debug(f"Reconnected to {self._host}:{self._port}")

    def send(self, data: bytes) -> None:
        """Send data through the socket.

        Args:
            data: Bytes to send

        Raises:
            RuntimeError: If socket is not connected
        """
        if self._sock is None:
            raise RuntimeError("Socket not connected. Call connect() first.")
        self._sock.sendall(data)

    def receive(self, buffer_size: int = 4096) -> bytes:
        """Receive data from the socket.

        Args:
            buffer_size: Maximum bytes to receive

        Returns:
            Received bytes

        Raises:
            RuntimeError: If socket is not connected
        """
        if self._sock is None:
            raise RuntimeError("Socket not connected. Call connect() first.")
        return self._sock.recv(buffer_size)

    def close(self) -> None:
        """Close the socket connection."""
        if self._sock:
            self._sock.close()
            self._sock = None
            self.logger.debug(f"Closed connection to {self._host}:{self._port}")

    def __enter__(self) -> "SocketManager":
        """Context manager entry."""
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:  # noqa: ANN001
        """Context manager exit."""
        self.close()
