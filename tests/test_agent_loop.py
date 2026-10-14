from typing import Any

import pytest

from agent import (
    AgentConfig,
    AgentStatus,
    BanditAgent,
    SSHResult,
    VerificationResult,
)
from agent.llm import OpenRouterRateLimitError


class FakeSSH:
    def __init__(self, responses: dict[str, SSHResult], connection_failure=None):
        self.responses = responses
        self.connection_failure = connection_failure
        self.connected = connection_failure is None
        self.closed = False
        self.commands: list[str] = []

    def connect(self):
        if self.connection_failure is not None:
            return self.connection_failure
        self.connected = True
        return None

    def is_connected(self):
        return self.connected

    def execute(self, command, timeout=None):
        self.commands.append(command)
        return self.responses.get(
            command,
            SSHResult(command=command, exit_code=0, stdout="(no output)"),
        )

    def close(self):
        self.closed = True


def make_config(
    decisions: list[Any],
    ssh: FakeSSH,
    verifier=None,
    max_steps: int = 4,
    max_seconds: int = 120,
):
    iterator = iter(decisions)

    def llm(prompt: str):
        try:
            value = next(iterator)
        except StopIteration as exc:
            raise AssertionError("LLM was called more often than expected") from exc
        if isinstance(value, Exception):
            raise value
        return value

    if verifier is None:
        verifier = lambda user, candidate: VerificationResult(
            success=candidate == "secretsecretsecretsecretsecretse",
            error_type=None if candidate == "secretsecretsecretsecretsecretse" else "authentication",
        )

    return AgentConfig(
        host="bandit.labs.overthewire.org",
        port=2220,
        username="bandit0",
        password="pw",
        model="fake",
        max_steps=max_steps,
        max_seconds=max_seconds,
        command_timeout=5,
        connect_timeout=5,
        llm=llm,
        ssh_factory=lambda *args, **kwargs: ssh,
        verifier=verifier,
        stop_requested=lambda: False,
    )


def test_agent_performs_multiple_attempts_before_success():
    ssh = FakeSSH(
        {
            "ls": SSHResult(command="ls", exit_code=0, stdout="readme"),
            "cat readme": SSHResult(
                command="cat readme",
                exit_code=0,
                stdout="The password you are looking for: secretsecretsecretsecretsecretse",
            ),
        }
    )
    decisions = [
        {"strategy": "list", "command": "ls", "hypothesis": "Inspect directory", "reason": "start"},
        {"strategy": "read", "command": "cat readme", "hypothesis": "Read candidate", "reason": "read readme"},
    ]
    config = make_config(decisions, ssh, max_steps=4)
    result = BanditAgent(config).run()

    assert result.status == AgentStatus.SOLVED
    assert result.attempts_count == 2
    assert ssh.commands == ["ls", "cat readme"]
    assert result.password == "secretsecretsecretsecretsecretse"
    assert result.verification_status == "verified"


def test_agent_stops_after_openrouter_rate_limit_instead_of_repeating_requests():
    ssh = FakeSSH({})
    decisions = [OpenRouterRateLimitError(retry_after=30)]
    config = make_config(decisions, ssh, max_steps=5)
    events = []
    config.status_callback = lambda status, details: events.append(details)

    result = BanditAgent(config).run()

    assert result.status == AgentStatus.ERROR
    assert result.attempts_count == 0
    assert ssh.commands == []
    assert "HTTP 429" in result.error
    assert "30 Sekunden" in result.error
    assert [event["phase"] for event in events if event.get("phase")] == [
        "ssh_connect",
        "llm_wait",
        "llm_rate_limited",
    ]
    assert result.memory is not None
    assert any(item.name == "llm_rate_limited" for item in result.memory.strategies)


def test_agent_reads_a_listed_dash_named_file_unambiguously():
    password = "secretsecretsecretsecretsecretse"
    ssh = FakeSSH(
        {
            "ls": SSHResult(command="ls", exit_code=0, stdout="-\n"),
            "cat ./-": SSHResult(
                command="cat ./-", exit_code=0, stdout=f"Password: {password}\n"
            ),
            "cat .bashrc": SSHResult(
                command="cat .bashrc", exit_code=0, stdout="configuration"
            ),
        }
    )
    config = make_config(
        [
            {"strategy": "list", "command": "ls", "hypothesis": "List home", "reason": "Inspect home"},
            {"strategy": "read", "command": "cat .bashrc", "hypothesis": "Read config", "reason": "LLM guess"},
        ],
        ssh,
        max_steps=4,
    )
    config.username = "bandit1"

    result = BanditAgent(config).run()

    assert result.status == AgentStatus.SOLVED
    assert ssh.commands == ["ls", "cat ./-"]
    assert result.password == password
    assert result.verification_status == "verified"


def test_verification_failure_does_not_report_solved():
    ssh = FakeSSH(
        {
            "cat readme": SSHResult(
                command="cat readme",
                exit_code=0,
                stdout="The password you are looking for: wrongwrongwrongwrongwrongwrongwn",
            ),
        }
    )
    decisions = [
        {"strategy": "read", "command": "cat readme", "hypothesis": "Read candidate", "reason": "read"},
        {"strategy": "list", "command": "ls", "hypothesis": "Maybe list", "reason": "retry"},
    ]
    config = make_config(decisions, ssh, max_steps=2)
    result = BanditAgent(config).run()

    assert result.status != AgentStatus.SOLVED
    assert result.password is None
    assert result.verification_status == "rejected"


def test_failed_command_is_recorded_and_agent_retries():
    ssh = FakeSSH(
        {
            "cat missing": SSHResult(
                command="cat missing",
                exit_code=1,
                stdout="",
                stderr="No such file or directory",
            ),
            "ls": SSHResult(command="ls", exit_code=0, stdout="readme"),
        }
    )
    decisions = [
        {"strategy": "read", "command": "cat missing", "hypothesis": "Try file", "reason": "try"},
        {"strategy": "list", "command": "ls", "hypothesis": "List files", "reason": "fallback"},
    ]
    config = make_config(decisions, ssh, max_steps=2)
    result = BanditAgent(config).run()

    assert result.status == AgentStatus.MAX_ATTEMPTS
    assert result.attempts_count == 2
    assert result.memory is not None
    assert result.memory.attempts[0].result.exit_code == 1
    assert "failed" in [s.outcome for s in result.memory.strategies]


def test_duplicate_command_is_blocked_after_first_execution():
    ssh = FakeSSH(
        {
            "ls": SSHResult(command="ls", exit_code=0, stdout="readme"),
        }
    )
    decisions = [
        {"strategy": "list", "command": "ls", "hypothesis": "List", "reason": "first"},
        {"strategy": "list", "command": "ls", "hypothesis": "List again", "reason": "again"},
        {"strategy": "list", "command": "ls", "hypothesis": "List again", "reason": "again"},
        {"strategy": "list", "command": "ls", "hypothesis": "List again", "reason": "again"},
    ]
    config = make_config(decisions, ssh, max_steps=6)
    result = BanditAgent(config).run()

    assert result.status == AgentStatus.NEEDS_INPUT
    assert ssh.commands == ["ls"]
    assert result.memory is not None
    assert result.memory.duplicate_count == 0
    assert any(record.name == "duplicate_command_suppressed" for record in result.memory.strategies)


def test_rejected_command_and_reason_are_given_to_next_llm_call_and_not_repeated():
    ssh = FakeSSH({"ls -la": SSHResult(command="ls -la", exit_code=0, stdout="readme")})
    decisions = [
        {"strategy": "list", "command": "ls -laZ", "hypothesis": "List files", "reason": "Inspect files"},
        {"strategy": "list", "command": "ls -laZ", "hypothesis": "List files again", "reason": "retry"},
        {"strategy": "list", "command": "ls -la", "hypothesis": "Show hidden files", "reason": "The level needs directory inspection"},
    ]
    config = make_config(decisions, ssh, max_steps=3)
    original_llm = config.llm
    prompts = []

    def capture_prompt(prompt):
        prompts.append(prompt)
        return original_llm(prompt)

    config.llm = capture_prompt
    result = BanditAgent(config).run()

    assert len(prompts) == 3
    assert "ls -laZ" in prompts[1]
    assert "Befehle, die von der zentralen Richtlinie abgelehnt wurden" in prompts[1]
    assert "Diese Option ist nicht für die freigegebenen Nur-Lese-Befehle zugelassen." in prompts[1]
    assert "Aktuelle zentrale Befehlsfreigabe" in prompts[1]
    assert "kurze ls-Optionen dürfen kombiniert werden" in prompts[1]
    assert "zum Beispiel -la" in prompts[1]
    assert "-la" in prompts[1]
    assert "ls -laZ" in prompts[2]
    assert ssh.commands == ["ls -la"]
    assert result.memory is not None
    assert result.memory.rejected_commands["ls -laZ"]
    assert any(record.name == "rejected_command_suppressed" for record in result.memory.strategies)


def test_failed_command_output_is_visible_and_repeated_command_is_suppressed():
    ssh = FakeSSH(
        {
            "cat missing": SSHResult(
                command="cat missing", exit_code=1, stderr="No such file or directory"
            ),
            "ls": SSHResult(command="ls", exit_code=0, stdout="readme"),
        }
    )
    decisions = [
        {"strategy": "read", "command": "cat missing", "hypothesis": "Read file", "reason": "Try file"},
        {"strategy": "read", "command": "cat missing", "hypothesis": "Read again", "reason": "Retry"},
        {"strategy": "list", "command": "ls", "hypothesis": "List observed directory", "reason": "Find actual names"},
    ]
    config = make_config(decisions, ssh, max_steps=3)
    original_llm = config.llm
    prompts = []
    config.llm = lambda prompt: (prompts.append(prompt), original_llm(prompt))[1]

    result = BanditAgent(config).run()

    assert "Fehlgeschlagene Befehle" in prompts[1]
    assert "No such file or directory" in prompts[1]
    assert ssh.commands == ["cat missing", "ls"]
    assert result.attempts_count == 2


def test_repeated_llm_failures_become_error():
    ssh = FakeSSH({})
    decisions = [ValueError("bad"), ValueError("bad"), ValueError("bad")]
    config = make_config(decisions, ssh, max_steps=5)
    result = BanditAgent(config).run()

    assert result.status == AgentStatus.ERROR


def test_authentication_failure_requires_user_input():
    auth_failure = SSHResult(
        command="<connect>",
        exit_code=None,
        error_type="authentication",
        error_message="Authentication failed.",
    )
    ssh = FakeSSH({}, connection_failure=auth_failure)
    config = make_config([], ssh, max_steps=1)
    result = BanditAgent(config).run()

    assert result.status == AgentStatus.NEEDS_INPUT
    assert result.error == "Authentifizierung für das aktuelle Level fehlgeschlagen."


def test_verification_connection_error_is_not_reported_as_wrong_password():
    ssh = FakeSSH({
        "cat readme": SSHResult(
            command="cat readme", exit_code=0,
            stdout="password: secretsecretsecretsecretsecretse",
        ),
        "ls": SSHResult(command="ls", exit_code=0, stdout="readme"),
    })
    verifier = lambda user, candidate: VerificationResult(
        success=False, error_type="connection", reason="verification server unavailable"
    )
    config = make_config(
        [{"strategy": "read", "command": "cat readme", "hypothesis": "Read", "reason": "read"},
         {"strategy": "list", "command": "ls", "hypothesis": "Retry", "reason": "retry"}],
        ssh, verifier=verifier, max_steps=2,
    )
    result = BanditAgent(config).run()

    assert result.status == AgentStatus.MAX_ATTEMPTS
    assert result.verification_status == "error"
    assert result.memory is not None
    assert "secretsecretsecretsecretsecretse" not in result.summary


def test_agent_config_rejects_non_bandit_targets():
    with pytest.raises(ValueError):
        AgentConfig(host="example.com", port=2222, username="user", password="pw")


def test_unapproved_command_is_never_executed():
    ssh = FakeSSH({"ls": SSHResult(command="ls", exit_code=0, stdout="readme")})
    config = make_config(
        [{"strategy": "list", "command": "ls", "hypothesis": "Inspect files", "reason": "list"}],
        ssh,
        max_steps=1,
    )
    config.command_approval = lambda command, details: False

    result = BanditAgent(config).run()

    assert result.status == AgentStatus.NEEDS_INPUT
    assert ssh.commands == []
    assert result.attempts_count == 0


def test_llm_candidate_without_tool_output_is_not_verified():
    ssh = FakeSSH({})
    verifier_calls = []

    def verifier(user, candidate):
        verifier_calls.append((user, candidate))
        return VerificationResult(success=True)

    config = make_config(
        [{
            "strategy": "guess", "command": None, "hypothesis": "Guess",
            "reason": "model guess", "password_candidate": "invented-candidate",
        }],
        ssh,
        verifier=verifier,
        max_steps=1,
    )

    result = BanditAgent(config).run()

    assert result.status != AgentStatus.SOLVED
    assert result.password is None
    assert verifier_calls == []


def test_learning_mode_offers_only_distinct_safe_candidates_and_executes_selected_one():
    ssh = FakeSSH({"ls -l": SSHResult(command="ls -l", exit_code=0, stdout="readme" )})
    decisions = [
        {"strategy": "inspect", "command": "ls", "hypothesis": "Dateien ansehen", "reason": "Start"},
        {"strategy": "detail", "command": "ls -l", "hypothesis": "Details ansehen", "reason": "Metadaten vergleichen"},
        {"strategy": "unsafe", "command": "ls; id", "hypothesis": "unsicher", "reason": "abgelehnt"},
        {"strategy": "duplicate", "command": "ls -l", "hypothesis": "Doppelung", "reason": "wiederholt"},
        {"strategy": "other", "command": "pwd", "hypothesis": "Arbeitsordner prüfen", "reason": "Pfad"},
    ]
    config = make_config(decisions, ssh, max_steps=1)
    config.learning_mode = True
    choices = []

    def approve(command, details):
        choices.extend(details["candidate_options"])
        return "ls -l"

    config.command_approval = approve
    result = BanditAgent(config).run()

    assert [item["command"] for item in choices] == ["ls", "ls -l", "pwd"]
    assert ssh.commands == ["ls -l"]
    assert result.attempts_count == 1


def test_user_hints_are_included_as_untrusted_data_in_agent_prompt():
    ssh = FakeSSH({"pwd": SSHResult(command="pwd", exit_code=0, stdout="/home/bandit0")})
    config = make_config(
        [{"strategy": "inspect", "command": "pwd", "hypothesis": "Pfad", "reason": "Prüft Ort"}],
        ssh,
        max_steps=1,
    )
    prompts = []

    def capture_llm(prompt):
        prompts.append(prompt)
        return {"strategy": "inspect", "command": "pwd", "hypothesis": "Pfad", "reason": "Prüft Ort"}

    config.llm = capture_llm
    config.user_hints = ["Die Datei heißt vielleicht -"]
    BanditAgent(config).run()

    assert "Die Datei heißt vielleicht -" in prompts[0]
    assert "untrusted observation data" in prompts[0]
