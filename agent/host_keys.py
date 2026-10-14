from __future__ import annotations

import base64
import hashlib
import socket
from pathlib import Path

import paramiko


BANDIT_HOST = "bandit.labs.overthewire.org"
BANDIT_PORT = 2220


def fetch_bandit_host_key(host: str, port: int, timeout: int = 8) -> paramiko.PKey:
    """Fetch the presented key without authenticating; callers must ask before pinning it."""
    sock = socket.create_connection((host, int(port)), timeout=timeout)
    transport = paramiko.Transport(sock)
    try:
        transport.start_client(timeout=timeout)
        return transport.get_remote_server_key()
    finally:
        transport.close()


def host_key_fingerprint(key: paramiko.PKey) -> str:
    digest = hashlib.sha256(key.asbytes()).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


def save_bandit_host_key(
    host: str,
    port: int,
    key: paramiko.PKey,
    *,
    known_hosts_path: Path | None = None,
) -> Path:
    """Persist an explicitly approved first-contact key in this runtime's known_hosts."""
    if host.strip().lower() != BANDIT_HOST or int(port) != BANDIT_PORT:
        raise ValueError(f"Hostschlüssel dürfen nur für {BANDIT_HOST}:{BANDIT_PORT} gespeichert werden.")

    path = known_hosts_path or (Path.home() / ".ssh" / "known_hosts")
    path.parent.mkdir(parents=True, exist_ok=True)
    host_keys = paramiko.HostKeys()
    if path.exists():
        host_keys.load(str(path))

    host_entry = f"[{BANDIT_HOST}]:{BANDIT_PORT}"
    existing = host_keys.lookup(host_entry)
    if existing:
        existing_key = existing.get(key.get_name())
        if existing_key is not None and existing_key != key:
            raise ValueError("Der gespeicherte Bandit-Hostschlüssel weicht ab. Nicht automatisch ersetzen.")

    host_keys.add(host_entry, key.get_name(), key)
    host_keys.save(str(path))
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return path
