import pytest

from agent.policy import normalize_command, validate_command


def test_normalize_command_collapses_whitespace():
    assert normalize_command("  ls   -la   /home  ") == "ls -la /home"


def test_validate_command_accepts_safe_read_only_command():
    ok, normalized = validate_command("  cat   ./readme  ")
    assert ok is True
    assert normalized == "cat ./readme"


def test_validate_command_rejects_shell_metacharacters():
    ok, reason = validate_command("ls -la && cat secret")
    assert ok is False
    assert "gesperrt" in reason.lower() or "metazeichen" in reason.lower()


def test_validate_command_rejects_blocked_program():
    ok, reason = validate_command("rm -rf /")
    assert ok is False
    assert "erlaubten" in reason.lower() or "leseliste" in reason.lower()


def test_validate_command_rejects_find_exec():
    ok, reason = validate_command("find / -name x -exec cat {} +")
    assert ok is False
    assert "find" in reason.lower()


def test_validate_command_requires_stdout_for_compression_tools():
    ok, reason = validate_command("gzip /tmp/file.gz")
    assert ok is False
    assert "stdout" in reason.lower() or "verändern" in reason.lower()


def test_validate_command_accepts_stdout_compression():
    ok, normalized = validate_command("gzip -cd archive.gz")
    assert ok is True
    assert normalized == "gzip -cd archive.gz"


@pytest.mark.parametrize("command", [
    "ls & whoami",
    "grep --include='*' pattern file",
    "cat --output=file input",
    "find / -name x -delete",
])
def test_validate_command_rejects_unsafe_shell_forms_and_options(command):
    ok, _reason = validate_command(command)
    assert ok is False
