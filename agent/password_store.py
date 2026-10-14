"""Local Bandit password store in the app's ignored private data folder."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Mapping


def password_store_path() -> Path:
    """Return the app-local credential file path (overrideable for deployments/tests)."""
    configured = os.environ.get("BANDIT_PASSWORD_STORE")
    if configured:
        return Path(configured).expanduser()
    return Path.home() / "Documents" / "Codex" / "BanditCTFAgent" / "passwords.json"


def _fallback_password_store_path() -> Path:
    return Path(tempfile.gettempdir()) / "BanditCTFAgent" / "passwords.json"


def load_passwords(path: Path | None = None) -> dict[str, str]:
    targets = [path] if path is not None else [password_store_path(), _fallback_password_store_path()]
    for target in targets:
        try:
            data = json.loads(target.read_text(encoding="utf-8"))
        except (FileNotFoundError, OSError, json.JSONDecodeError):
            continue
        if isinstance(data, dict):
            return {
                str(user): str(password)
                for user, password in data.items()
                if isinstance(user, str) and user.startswith("bandit") and isinstance(password, str)
            }
    return {}


def save_passwords(passwords: Mapping[str, str], path: Path | None = None) -> Path:
    target = path or password_store_path()
    safe_data = {
        str(user): str(password)
        for user, password in passwords.items()
        if str(user).startswith("bandit") and isinstance(password, str)
    }

    targets = [target] if path is not None or os.environ.get("BANDIT_PASSWORD_STORE") else [
        target, _fallback_password_store_path()
    ]
    last_error = None
    for candidate in targets:
        try:
            candidate.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            if os.name != "nt":
                try:
                    candidate.parent.chmod(0o700)
                except OSError:
                    pass
            fd = os.open(candidate, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(safe_data, stream, ensure_ascii=False, indent=2)
                stream.write("\n")
            if os.name != "nt":
                try:
                    candidate.chmod(0o600)
                except OSError:
                    pass
            return candidate
        except OSError as exc:
            last_error = exc
    raise OSError(f"Passwortspeicher ist nicht beschreibbar: {last_error}") from last_error
