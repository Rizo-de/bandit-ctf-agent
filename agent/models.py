from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from .policy import normalize_command
from .status import AgentStatus


@dataclass
class SSHResult:
    """Result of a single SSH command execution."""

    command: str = ""
    exit_code: Optional[int] = None
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    duration: float = 0.0
    error_type: Optional[str] = None
    error_message: Optional[str] = None

    @property
    def success(self) -> bool:
        return (
            self.error_type is None
            and not self.timed_out
            and self.exit_code == 0
        )


@dataclass
class LLMDecision:
    """Validated structured decision returned by the language model."""

    hypothesis: str = ""
    summary: str = ""
    strategy: str = ""
    command: Optional[str] = None
    expected_output: str = ""
    password_candidate: Optional[str] = None
    confidence: float = 0.0
    reason: str = ""
    raw: dict[str, Any] = field(default_factory=dict, repr=False)


@dataclass
class StrategyRecord:
    name: str
    command: Optional[str]
    outcome: str
    reason: str
    step: int


@dataclass
class Attempt:
    step: int
    command: str
    strategy: str
    result: SSHResult
    hypothesis: str
    started_at: float
    finished_at: float = 0.0


@dataclass
class AgentMemory:
    """In-process memory for one Bandit level."""

    level: str
    goal: str
    max_attempts: int
    started_at: float
    attempts: list[Attempt] = field(default_factory=list)
    strategies: list[StrategyRecord] = field(default_factory=list)
    hypotheses: list[str] = field(default_factory=list)
    command_fingerprints: set[str] = field(default_factory=set)
    command_outcomes: dict[str, str] = field(default_factory=dict)
    tried_candidates: list[str] = field(default_factory=list)
    rejected_candidates: set[str] = field(default_factory=set)
    candidate_passwords: list[str] = field(default_factory=list)
    last_hypothesis: str = ""
    last_command: Optional[str] = None
    last_output: str = ""
    last_exit_code: Optional[int] = None
    last_status: AgentStatus = AgentStatus.RUNNING
    verification_status: str = "not_verified"
    verified_password: Optional[str] = None
    duplicate_count: int = 0
    no_action_count: int = 0
    consecutive_failures: int = 0
    finished_at: Optional[float] = None
    error_summary: Optional[str] = None

    def has_tried(self, command: str) -> bool:
        return normalize_command(command) in self.command_fingerprints

    def record_attempt(self, attempt: Attempt) -> None:
        self.attempts.append(attempt)
        fingerprint = normalize_command(attempt.command)
        self.command_fingerprints.add(fingerprint)
        self.command_outcomes[fingerprint] = attempt.result.success and "success" or "failed"
        self.last_command = attempt.command
        self.last_output = attempt.result.stdout
        if attempt.result.stderr:
            self.last_output = (
                self.last_output
                + ("\n" if self.last_output else "")
                + "[stderr] " + attempt.result.stderr
            )
        self.last_exit_code = attempt.result.exit_code
        self.last_status = (
            AgentStatus.RUNNING if attempt.result.success else AgentStatus.RETRY
        )

    def record_strategy(self, record: StrategyRecord) -> None:
        self.strategies.append(record)

    def add_hypothesis(self, text: str, confidence: float = 0.0) -> None:
        cleaned = text.strip()
        if not cleaned:
            return
        if self.hypotheses and self.hypotheses[-1] == cleaned:
            return
        self.hypotheses.append(cleaned)

    def remember_candidate(self, candidate: str) -> None:
        if candidate and candidate not in self.candidate_passwords:
            self.candidate_passwords.append(candidate)

    def final_summary_data(self) -> dict[str, Any]:
        return {
            "level": self.level,
            "attempts": len(self.attempts),
            "verification_status": self.verification_status,
            "verified_password": self.verified_password is not None,
            "last_hypothesis": self.last_hypothesis,
            "last_command": self.last_command,
            "last_exit_code": self.last_exit_code,
            "error_summary": self.error_summary,
        }


@dataclass
class AgentResult:
    status: AgentStatus
    level: str
    attempts_count: int
    summary: str
    password: Optional[str] = None
    duration: float = 0.0
    memory: Optional[AgentMemory] = None
    last_command: Optional[str] = None
    last_output: str = ""
    verification_status: str = "not_verified"
    error: Optional[str] = None