from __future__ import annotations

import re
import time
from dataclasses import dataclass
from typing import Callable, Optional

from .models import SSHResult
from .ssh import BanditSSH


def next_level_username(username: str) -> str:
    match = re.fullmatch(r"bandit(\d+)", username.strip(), flags=re.IGNORECASE)
    if not match:
        raise ValueError(f"Cannot derive the next Bandit level from {username!r}.")
    return f"bandit{int(match.group(1)) + 1}"


@dataclass
class VerificationResult:
    success: bool
    next_user: Optional[str] = None
    exit_code: Optional[int] = None
    output: str = ""
    reason: str = ""
    error_type: Optional[str] = None
    duration: float = 0.0

    @property
    def failed(self) -> bool:
        return not self.success


class BanditPasswordVerifier:
    """
    Independently verify a candidate by logging into the next Bandit level.

    The verifier never logs the candidate itself. Its SSH connection is created
    with the candidate as password and then asked to run a harmless check.
    """

    def __init__(
        self,
        host: str,
        port: int,
        *,
        connect_timeout: int = 8,
        command_timeout: int = 8,
        ssh_factory: Callable[..., BanditSSH] | None = None,
    ) -> None:
        self.host = host
        self.port = port
        self.connect_timeout = connect_timeout
        self.command_timeout = command_timeout
        self._ssh_factory = ssh_factory or BanditSSH

    def __call__(self, current_user: str, candidate: str) -> VerificationResult:
        started = time.monotonic()
        try:
            next_user = next_level_username(current_user)
        except ValueError as exc:
            return VerificationResult(
                success=False,
                reason=str(exc),
                error_type="verification",
                duration=time.monotonic() - started,
            )

        ssh = self._ssh_factory(
            self.host,
            self.port,
            next_user,
            candidate,
            connect_timeout=self.connect_timeout,
            command_timeout=self.command_timeout,
        )

        try:
            connection_failure = ssh.connect()
            if connection_failure is not None:
                error_type = connection_failure.error_type or "connection"
                if error_type == "authentication":
                    reason = "Passwortkandidat wurde vom nächsten Level abgelehnt."
                elif error_type == "timeout":
                    reason = "Zeitüberschreitung bei der Verifikationsverbindung."
                elif error_type == "host_key":
                    reason = "Host-Key-Prüfung der Verifikationsverbindung fehlgeschlagen."
                else:
                    reason = "Verbindung zum nächsten Level konnte nicht aufgebaut werden."
                return VerificationResult(
                    success=False,
                    next_user=next_user,
                    reason=reason,
                    error_type=error_type,
                    duration=time.monotonic() - started,
                )

            result: SSHResult = ssh.execute("whoami", timeout=self.command_timeout)
            ssh.close()
            output = (result.stdout or "").strip()
            if result.error_type:
                return VerificationResult(
                    success=False,
                    next_user=next_user,
                    exit_code=result.exit_code,
                    output=output,
                    reason=f"Verifikationsbefehl fehlgeschlagen: {result.error_message or result.error_type}",
                    error_type=result.error_type,
                    duration=time.monotonic() - started,
                )
            if result.exit_code != 0:
                return VerificationResult(
                    success=False,
                    next_user=next_user,
                    exit_code=result.exit_code,
                    output=output,
                    reason="Verifikationsbefehl hat einen fehlerhaften Exit-Code geliefert.",
                    error_type="command",
                    duration=time.monotonic() - started,
                )
            if output != next_user:
                return VerificationResult(
                    success=False,
                    next_user=next_user,
                    exit_code=result.exit_code,
                    output=output,
                    reason="Das nächste Level hat einen unerwarteten Benutzer zurückgemeldet.",
                    error_type="verification",
                    duration=time.monotonic() - started,
                )

            return VerificationResult(
                success=True,
                next_user=next_user,
                exit_code=result.exit_code,
                output=output,
                reason="Passwortkandidat wurde durch Login am nächsten Level bestätigt.",
                error_type=None,
                duration=time.monotonic() - started,
            )
        except Exception as exc:
            try:
                ssh.close()
            except Exception:
                pass
            return VerificationResult(
                success=False,
                next_user=next_user,
                reason=f"Unerwarteter Fehler bei der Verifikation: {type(exc).__name__}: {exc}",
                error_type="unknown",
                duration=time.monotonic() - started,
            )