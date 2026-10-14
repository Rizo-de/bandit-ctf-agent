from __future__ import annotations

import socket
import time
from typing import Optional

import paramiko

from .models import SSHResult


class BanditSSH:
    """A small, reusable Paramiko connection with bounded reads and timeouts."""

    def __init__(
        self,
        host: str,
        port: int,
        username: str,
        password: str,
        *,
        connect_timeout: int = 8,
        command_timeout: int = 15,
        max_output_bytes: int = 20000,
    ) -> None:
        self.host = host
        self.port = int(port)
        self.username = username
        self.password = password
        self.connect_timeout = connect_timeout
        self.command_timeout = command_timeout
        self.max_output_bytes = max_output_bytes

        self._client: Optional[paramiko.SSHClient] = None
        self._connected = False
        self.last_error_type: Optional[str] = None
        self.last_error_message: Optional[str] = None

    def _classify_exception(self, exc: Exception) -> str:
        if isinstance(exc, paramiko.AuthenticationException):
            return "authentication"
        if isinstance(exc, paramiko.BadHostKeyException):
            return "host_key"
        if isinstance(exc, (socket.timeout, TimeoutError)):
            return "timeout"
        if isinstance(exc, (paramiko.SSHException, OSError, EOFError)):
            return "connection"
        return "unknown"

    def _record_error(self, exc: Exception) -> str:
        error_type = self._classify_exception(exc)
        self.last_error_type = error_type
        self.last_error_message = f"{type(exc).__name__}: {exc}"
        return error_type

    def connect(self) -> Optional[SSHResult]:
        """Connect if needed. Return None on success, or a failure result."""
        if self._connected and self._client is not None:
            transport = self._client.get_transport()
            if transport is not None and transport.is_active():
                self.last_error_type = None
                self.last_error_message = None
                return None
            self._connected = False
            if self._client is not None:
                try:
                    self._client.close()
                except Exception:
                    pass
            self._client = None

        client = paramiko.SSHClient()
        client.load_system_host_keys()
        # Require a key from the user's/system known_hosts. Never trust an
        # unknown server key automatically (including Bandit's first contact).
        client.set_missing_host_key_policy(paramiko.RejectPolicy())

        try:
            client.connect(
                hostname=self.host,
                port=self.port,
                username=self.username,
                password=self.password,
                timeout=self.connect_timeout,
                banner_timeout=self.connect_timeout,
                auth_timeout=self.connect_timeout,
                look_for_keys=False,
                allow_agent=False,
            )
        except Exception as exc:
            try:
                client.close()
            except Exception:
                pass
            error_type = self._record_error(exc)
            return SSHResult(
                command="<connect>",
                exit_code=None,
                error_type=error_type,
                error_message=self.last_error_message,
            )

        self._client = client
        self._connected = True
        self.last_error_type = None
        self.last_error_message = None
        return None

    def is_connected(self) -> bool:
        if not self._connected or self._client is None:
            return False
        transport = self._client.get_transport()
        return transport is not None and transport.is_active()

    def _read_limited(self, stream, limit: int) -> str:
        chunks: list[bytes] = []
        total = 0
        eof = False
        # Paramiko file objects support read(n), but a single read can block.
        # Use a modest loop with the channel timeout already configured.
        while total < limit and not eof:
            try:
                data = stream.read(min(4096, limit - total + 1))
            except socket.timeout:
                break
            except Exception:
                break
            if not data:
                eof = True
                continue
            if total + len(data) > limit:
                chunks.append(data[: limit - total])
                total = limit
                eof = True
            else:
                chunks.append(data)
                total += len(data)
        raw = b"".join(chunks)
        return raw.decode("utf-8", errors="replace")

    def execute(self, command: str, timeout: Optional[int] = None) -> SSHResult:
        effective_timeout = self.command_timeout if timeout is None else timeout
        start = time.monotonic()

        if not self.is_connected():
            failure = self.connect()
            if failure is not None:
                duration = time.monotonic() - start
                return SSHResult(
                    command=command,
                    exit_code=None,
                    timed_out=False,
                    duration=duration,
                    error_type=failure.error_type,
                    error_message=failure.error_message,
                )

        assert self._client is not None
        timed_out = False
        exit_code: Optional[int] = None
        stdout_text = ""
        stderr_text = ""
        error_type: Optional[str] = None
        error_message: Optional[str] = None

        try:
            _stdin, stdout, stderr = self._client.exec_command(command, timeout=effective_timeout)
            channel = stdout.channel
            channel.settimeout(effective_timeout)

            deadline = start + effective_timeout
            while not channel.exit_status_ready():
                if time.monotonic() >= deadline:
                    timed_out = True
                    try:
                        channel.close()
                    except Exception:
                        pass
                    break
                time.sleep(0.05)

            if timed_out:
                try:
                    stdout_text = self._read_limited(stdout, self.max_output_bytes)
                    stderr_text = self._read_limited(stderr, self.max_output_bytes // 2)
                except Exception:
                    pass
                error_type = "timeout"
                error_message = "Zeitlimit für den Befehl überschritten."
            else:
                exit_code = channel.recv_exit_status()
                stdout_text = self._read_limited(stdout, self.max_output_bytes)
                stderr_text = self._read_limited(stderr, self.max_output_bytes // 2)
        except Exception as exc:
            error_type = self._classify_exception(exc)
            error_message = f"{type(exc).__name__}: {exc}"
            self._connected = False
            if self._client is not None:
                try:
                    self._client.close()
                except Exception:
                    pass
            self._client = None
            try:
                stdout_text = stdout_text or ""
                stderr_text = stderr_text or ""
            except Exception:
                stdout_text = ""
                stderr_text = ""

        duration = time.monotonic() - start
        if error_type in {"connection", "authentication", "host_key"}:
            self._connected = False

        return SSHResult(
            command=command,
            exit_code=exit_code,
            stdout=stdout_text,
            stderr=stderr_text,
            timed_out=timed_out,
            duration=duration,
            error_type=error_type,
            error_message=error_message,
        )

    def close(self) -> None:
        self.disconnect()

    def disconnect(self) -> None:
        if self._client is not None:
            try:
                self._client.close()
            except Exception:
                pass
        self._client = None
        self._connected = False
