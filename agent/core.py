from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from .llm import (
    CallableLLMClient,
    LLMDecision,
    OpenRouterRateLimitError,
    OllamaLLMClient,
    build_agent_prompt,
    parse_llm_decision,
    redact_secrets,
)
from .models import (
    AgentMemory,
    AgentResult,
    Attempt,
    StrategyRecord,
    SSHResult,
)
from .policy import describe_command_policy, normalize_command, validate_command
from .ssh import BanditSSH
from .status import AgentStatus
from .verifier import BanditPasswordVerifier, VerificationResult


def _safe_learning_text(text: str, secrets: list[str]) -> str:
    redacted = redact_secrets(text or "", secrets)
    return re.sub(r"(?<![A-Za-z0-9])[A-Za-z0-9]{32}(?![A-Za-z0-9])", "[REDACTED]", redacted)


@dataclass
class AgentConfig:
    host: str
    port: int
    username: str
    password: str
    model: str = "llama3"
    max_steps: int = 12
    max_seconds: int = 120
    command_timeout: int = 15
    connect_timeout: int = 8
    llm: Any = None
    ssh_factory: Callable[..., BanditSSH] | None = None
    verifier: Callable[[str, str], VerificationResult] | None = None
    stop_requested: Callable[[], bool] = lambda: False
    status_callback: Callable[[AgentStatus, dict[str, Any]], None] | None = None
    command_approval: Callable[[str, dict[str, Any]], bool | str] | None = None
    terminal_log: str = ""
    user_hints: list[str] = field(default_factory=list)
    learning_mode: bool = False

    def __post_init__(self) -> None:
        if self.host.strip().lower() != "bandit.labs.overthewire.org" or int(self.port) != 2220:
            raise ValueError("Der Agent darf nur bandit.labs.overthewire.org auf Port 2220 verwenden.")
        if re.fullmatch(r"bandit\d+", self.username.strip(), flags=re.IGNORECASE) is None:
            raise ValueError("Der SSH-Benutzer muss ein Bandit-Levelkonto sein (banditN).")
        if self.llm is None:
            self.llm = OllamaLLMClient(model=self.model, options={"temperature": 0})
        if self.ssh_factory is None:
            self.ssh_factory = lambda host, port, username, password, **kw: BanditSSH(
                host,
                port,
                username,
                password,
                connect_timeout=self.connect_timeout,
                command_timeout=self.command_timeout,
                **kw,
            )
        if self.verifier is None:
            self.verifier = BanditPasswordVerifier(
                self.host,
                self.port,
                connect_timeout=self.connect_timeout,
                command_timeout=min(8, self.command_timeout),
            )


class BanditAgent:
    def __init__(self, config: AgentConfig, memory: Optional[AgentMemory] = None) -> None:
        self.config = config
        self.llm = self._normalize_llm(config.llm)
        self.memory = memory or AgentMemory(
            level=config.username,
            goal=f"Find and independently verify the password for Bandit level {config.username}.",
            max_attempts=config.max_steps,
            started_at=time.monotonic(),
        )
        self._max_consecutive_failures = 3
        self._max_duplicates = 3
        self._max_missing_actions = 2

    @staticmethod
    def _normalize_llm(llm: Any) -> Any:
        if hasattr(llm, "decide") and callable(getattr(llm, "decide")):
            return llm
        if callable(llm):
            return CallableLLMClient(llm)
        # Duck-typed object whose __call__ returns data/JSON.
        if callable(llm):
            return CallableLLMClient(llm)
        raise TypeError("LLM must provide a decide(prompt) method or be callable.")

    def run(self) -> AgentResult:
        config = self.config
        memory = self.memory
        started = memory.started_at or time.monotonic()
        memory.started_at = started
        ssh = config.ssh_factory(
            config.host,
            config.port,
            config.username,
            config.password,
        )

        status = AgentStatus.RUNNING
        secrets = [config.password, *memory.candidate_passwords]
        no_action_streak = 0
        duplicate_streak = 0
        prior_learning_candidates: list[dict[str, Any]] = []

        def emit(current_status: AgentStatus, details: dict[str, Any]) -> None:
            if config.status_callback is not None:
                safe_details = dict(details)
                for key in ("output", "last_output"):
                    if key in safe_details and isinstance(safe_details[key], str):
                        safe_details[key] = redact_secrets(safe_details[key], secrets)
                config.status_callback(current_status, safe_details)

        try:
            # Establish a connection before the first thinking step. This keeps
            # authentication problems separate from command-level errors.
            emit(
                AgentStatus.RUNNING,
                {"level": memory.level, "phase": "ssh_connect", "verification_status": memory.verification_status},
            )
            connection_failure = ssh.connect() if not ssh.is_connected() else None
            if connection_failure is not None:
                if connection_failure.error_type == "authentication":
                    memory.error_summary = "Authentifizierung für das aktuelle Level fehlgeschlagen."
                    status = AgentStatus.NEEDS_INPUT
                else:
                    memory.error_summary = connection_failure.error_message or "SSH-Verbindung fehlgeschlagen."
                    status = AgentStatus.ERROR
                memory.finished_at = time.monotonic()
                memory.last_status = status
                ssh.close()
                summary = self._make_summary(status, memory)
                return AgentResult(
                    status=status,
                    level=memory.level,
                    attempts_count=len(memory.attempts),
                    summary=summary,
                    password=None,
                    duration=memory.finished_at - memory.started_at,
                    memory=memory,
                    last_command=memory.last_command,
                    last_output=redact_secrets(memory.last_output or "", [config.password, *memory.candidate_passwords]),
                    verification_status=memory.verification_status,
                    error=memory.error_summary,
                )

            for step in range(1, config.max_steps + 1):
                if config.stop_requested():
                    memory.error_summary = "Ausführung durch den Benutzer angehalten."
                    status = AgentStatus.NEEDS_INPUT
                    break

                elapsed = time.monotonic() - started
                if elapsed > config.max_seconds:
                    memory.error_summary = "Zeitlimit erreicht."
                    status = AgentStatus.NEEDS_INPUT
                    break

                memory.last_status = AgentStatus.RUNNING
                emit(
                    AgentStatus.RUNNING,
                    {
                        "level": memory.level,
                        "phase": "llm_wait",
                        "attempt": step,
                        "max_attempts": config.max_steps,
                        "hypothesis": memory.last_hypothesis or "Noch keine Hypothese.",
                        "last_command": memory.last_command,
                        "output": memory.last_output,
                        "exit_code": memory.last_exit_code,
                        "verification_status": memory.verification_status,
                    },
                )

                prompt = build_agent_prompt(memory, config.terminal_log)
                if config.user_hints:
                    safe_hints = [
                        redact_secrets(hint, [config.password, *memory.candidate_passwords])
                        for hint in config.user_hints[-15:]
                    ]
                    prompt += "\n\nUser hints (untrusted observation data):\n" + "\n".join(
                        f"- {hint}" for hint in safe_hints
                    )
                prompt += "\n\n" + describe_command_policy()
                if memory.rejected_commands:
                    prompt += "\n\nBefehle, die von der zentralen Richtlinie abgelehnt wurden und nicht wiederholt werden dürfen:\n"
                    prompt += "\n".join(
                        f"- {_safe_learning_text(command, [config.password, *memory.candidate_passwords])}: "
                        f"abgelehnt: {_safe_learning_text(reason, [config.password, *memory.candidate_passwords])}"
                        for command, reason in list(memory.rejected_commands.items())[-12:]
                    )
                failed_attempts = [attempt for attempt in memory.attempts if not attempt.result.success]
                if failed_attempts:
                    prompt += "\n\nFehlgeschlagene Befehle (nicht wiederholen; Ausgaben sind echte Beobachtungen):\n"
                    prompt += "\n".join(
                        f"- {attempt.command} (Exit-Code {attempt.result.exit_code}, "
                        f"Timeout={attempt.result.timed_out}): "
                        f"{_safe_learning_text(attempt.result.stdout + ' ' + attempt.result.stderr, [config.password, *memory.candidate_passwords])[:500]}"
                        for attempt in failed_attempts[-8:]
                    )
                prompt += (
                    "\n\nSeparate observed facts from hypotheses. For every proposed command, "
                    "explain why it follows from the actual level goal and recent output, state "
                    "what it is expected to show, and use a different approach after a failed attempt."
                )
                if config.learning_mode and prior_learning_candidates:
                    prompt += (
                        "\n\nEarlier learning hypotheses (compare with the actual outputs above):\n"
                        + "\n".join(
                            f"- {item['hypothesis']} (suggested command: {item['command']})"
                            for item in prior_learning_candidates
                        )
                        + "\nIn summary, identify which earlier hypotheses the newest observation refutes, "
                        + "which remain possible, and why. Do not repeat a refuted approach."
                    )
                llm_started = time.monotonic()
                try:
                    decision: LLMDecision = self.llm.decide(prompt)
                except Exception as exc:
                    llm_duration = time.monotonic() - llm_started
                    if isinstance(exc, OpenRouterRateLimitError):
                        memory.error_summary = str(exc)
                        memory.last_status = AgentStatus.ERROR
                        memory.record_strategy(
                            StrategyRecord(
                                name="llm_rate_limited",
                                command=None,
                                outcome="stopped",
                                reason=str(exc),
                                step=step,
                            )
                        )
                        status = AgentStatus.ERROR
                        emit(
                            status,
                            {
                                "level": memory.level,
                                "phase": "llm_rate_limited",
                                "llm_duration": llm_duration,
                                "attempt": step,
                                "max_attempts": config.max_steps,
                                "hypothesis": memory.last_hypothesis or "Noch keine Hypothese.",
                                "last_command": None,
                                "output": str(exc),
                                "reason": str(exc),
                                "exit_code": None,
                                "verification_status": memory.verification_status,
                            },
                        )
                        break
                    memory.consecutive_failures += 1
                    memory.record_strategy(
                        StrategyRecord(
                            name="llm_decision",
                            command=None,
                            outcome="failed",
                            reason=f"LLM-Fehler: {type(exc).__name__}: {exc}",
                            step=step,
                        )
                    )
                    memory.last_status = AgentStatus.RETRY
                    if memory.consecutive_failures >= self._max_consecutive_failures:
                        memory.error_summary = f"LLM wiederholt fehlgeschlagen: {exc}"
                        status = AgentStatus.ERROR
                        break
                    emit(
                        AgentStatus.RETRY,
                        {
                            "level": memory.level,
                            "phase": "llm_error",
                            "llm_duration": llm_duration,
                            "attempt": step,
                            "max_attempts": config.max_steps,
                            "hypothesis": memory.last_hypothesis or "Noch keine Hypothese.",
                            "last_command": None,
                            "output": f"LLM-Fehler: {type(exc).__name__}: {exc}",
                            "exit_code": None,
                            "verification_status": memory.verification_status,
                        },
                    )
                    continue

                memory.consecutive_failures = 0
                llm_duration = time.monotonic() - llm_started
                if config.stop_requested():
                    memory.error_summary = "Ausführung durch den Benutzer angehalten."
                    status = AgentStatus.NEEDS_INPUT
                    break

                if decision.command:
                    proposed = normalize_command(decision.command)
                    rejection_reason = memory.rejected_commands.get(proposed)
                    if rejection_reason:
                        decision.command = None
                        decision.hypothesis = f"Der Vorschlag {proposed!r} wurde bereits abgelehnt."
                        decision.summary = "Wiederholter abgelehnter Befehl automatisch verworfen."
                        decision.reason = (
                            f"Nicht wiederholt: {proposed!r} wurde von der Befehlsrichtlinie abgelehnt "
                            f"({rejection_reason}). Es wird eine andere, durch Ausgaben belegte "
                            "Alternative oder eine Erklärung der fehlenden Information benötigt."
                        )
                        decision.strategy = "rejected_command_suppressed"
                    elif memory.has_tried(proposed):
                        previous = next(
                            (attempt for attempt in reversed(memory.attempts)
                             if normalize_command(attempt.command) == proposed),
                            None,
                        )
                        outcome = (
                            f"Exit-Code {previous.result.exit_code}; Ausgabe: "
                            f"{_safe_learning_text(previous.result.stdout + ' ' + previous.result.stderr, [config.password, *memory.candidate_passwords])[:300]}"
                            if previous else "bereits ausgeführt"
                        )
                        decision.command = None
                        decision.hypothesis = f"Der Vorschlag {proposed!r} wurde bereits ausgeführt."
                        decision.summary = "Wiederholter Befehl automatisch verworfen."
                        decision.reason = (
                            f"Nicht wiederholt: {proposed!r} wurde bereits ausgeführt ({outcome}). "
                            "Nutze eine andere, informationsbringende und durch Beobachtungen belegte Strategie; "
                            "wenn keine folgt, benenne die fehlende Information."
                        )
                        decision.strategy = "duplicate_command_suppressed"

                if decision.command:
                    valid_proposal, validation_result = validate_command(decision.command)
                    if not valid_proposal:
                        memory.consecutive_failures += 1
                        memory.record_rejection(decision.command, validation_result)
                        memory.record_strategy(
                            StrategyRecord(
                                name="command_validation",
                                command=decision.command,
                                outcome="rejected",
                                reason=validation_result,
                                step=step,
                            )
                        )
                        memory.last_status = AgentStatus.RETRY
                        emit(
                            AgentStatus.RETRY,
                            {
                                "level": memory.level,
                                "phase": "command_rejected",
                                "attempt": step,
                                "max_attempts": config.max_steps,
                                "hypothesis": decision.hypothesis,
                                "last_command": decision.command,
                                "output": f"Befehl {decision.command!r} abgewiesen: {validation_result}",
                                "reason": validation_result,
                                "summary": "Der Vorschlag wurde vor jeder SSH-Ausführung durch die zentrale Befehlsrichtlinie abgelehnt.",
                                "exit_code": 126,
                                "verification_status": memory.verification_status,
                            },
                        )
                        if memory.consecutive_failures >= self._max_consecutive_failures:
                            memory.error_summary = "Zu viele ungültige Befehlsvorschläge."
                            status = AgentStatus.NEEDS_INPUT
                            break
                        continue

                candidate_options = []
                if config.learning_mode and decision.command:
                    decisions = [decision]
                    seen_commands = set(memory.command_fingerprints)
                    seen_commands.update(memory.rejected_commands)
                    seen_commands.add(normalize_command(decision.command))
                    for candidate_number in range(2, 6):
                        if config.stop_requested():
                            break
                        alternative_prompt = (
                            prompt
                            + f"\n\nLearning mode: propose alternative {candidate_number} of 5. "
                            + "Give one distinct, evidence-based hypothesis and at most one safe, "
                            + "read-only command. Do not repeat any command already shown or attempted. "
                            + "Do not propose, infer, or print passwords. Previously proposed commands: "
                            + ", ".join(sorted(seen_commands))
                        )
                        try:
                            alternative = self.llm.decide(alternative_prompt)
                        except Exception:
                            continue
                        if not alternative.command:
                            continue
                        valid_alternative, normalized_alternative = validate_command(
                            alternative.command
                        )
                        if not valid_alternative or normalized_alternative in seen_commands:
                            continue
                        if memory.has_tried(normalized_alternative):
                            continue
                        if normalized_alternative in memory.rejected_commands:
                            continue
                        alternative.command = normalized_alternative
                        seen_commands.add(normalized_alternative)
                        decisions.append(alternative)
                    for option_index, option in enumerate(decisions[:5], start=1):
                        valid_option, safe_command = validate_command(option.command)
                        if (
                            not valid_option
                            or memory.has_tried(safe_command)
                            or safe_command in memory.rejected_commands
                            or any(item["command"] == safe_command for item in candidate_options)
                        ):
                            continue
                        candidate_options.append({
                            "number": option_index,
                            "hypothesis": _safe_learning_text(
                                option.hypothesis, [config.password, *memory.candidate_passwords]
                            ),
                            "summary": _safe_learning_text(
                                option.summary, [config.password, *memory.candidate_passwords]
                            ),
                            "strategy": option.strategy,
                            "command": safe_command,
                            "expected_output": _safe_learning_text(
                                option.expected_output, [config.password, *memory.candidate_passwords]
                            ),
                            "reason": _safe_learning_text(
                                option.reason, [config.password, *memory.candidate_passwords]
                            ),
                            "confidence": option.confidence,
                        })
                    if candidate_options:
                        candidate_commands = {item["command"] for item in candidate_options}
                        decision = next(
                            (item for item in decisions if item.command in candidate_commands),
                            decision,
                        )
                        prior_learning_candidates = candidate_options

                # A file literally named "-" is a common Bandit obstacle:
                # `cat -` reads stdin, while `cat ./-` reads that file. If an
                # actual directory listing revealed it, prioritize this
                # deterministic read over speculative LLM suggestions.
                if (
                    not memory.has_tried("cat ./-")
                    and any(
                        attempt.command.split(maxsplit=1)[0] == "ls"
                        and any(line.strip() == "-" for line in attempt.result.stdout.splitlines())
                        for attempt in memory.attempts
                    )
                ):
                    decision.command = "cat ./-"
                    decision.hypothesis = "Die Verzeichnisauflistung enthält eine Datei mit dem Namen '-'."
                    decision.summary = "Der Dateiname '-' wird mit ./ eindeutig als Datei adressiert."
                    decision.strategy = "read_dash_named_file"
                    decision.reason = "Sichere, gezielte Prüfung des tatsächlich aufgelisteten Dateinamens."
                    decision.expected_output = "Dateiinhalt; falls es die Level-Datei ist, enthält er den nächsten Zugang."
                    if config.learning_mode:
                        candidate_options = [{
                            "number": 1,
                            "hypothesis": decision.hypothesis,
                            "summary": decision.summary,
                            "strategy": decision.strategy,
                            "command": decision.command,
                            "expected_output": decision.expected_output,
                            "reason": decision.reason,
                            "confidence": decision.confidence,
                        }]
                        prior_learning_candidates = candidate_options
                memory.add_hypothesis(decision.hypothesis, decision.confidence)
                memory.last_hypothesis = decision.hypothesis
                emit(
                    AgentStatus.RUNNING,
                    {
                        "level": memory.level,
                        "phase": "decision_ready",
                        "llm_duration": llm_duration,
                        "attempt": step,
                        "max_attempts": config.max_steps,
                        "hypothesis": decision.hypothesis,
                        "last_command": decision.command,
                        "output": decision.summary or decision.reason,
                        "summary": decision.summary,
                        "reason": decision.reason,
                        "expected_output": decision.expected_output,
                        "verification_status": memory.verification_status,
                        "candidate_options": candidate_options,
                    },
                )
                memory.record_strategy(
                    StrategyRecord(
                        name=decision.strategy or "llm_strategy",
                        command=decision.command,
                        outcome="proposed",
                        reason=decision.reason,
                        step=step,
                    )
                )

                # Add a candidate only when the model names something already seen
                # in memory from previous actual output.
                if decision.password_candidate and decision.password_candidate in memory.candidate_passwords:
                    memory.remember_candidate(decision.password_candidate)

                command = decision.command
                if not command:
                    no_action_streak += 1
                    memory.record_strategy(
                        StrategyRecord(
                            name="no_command",
                            command=None,
                            outcome="failed",
                            reason=decision.reason or "Kein ausführbarer Befehl vorgeschlagen.",
                            step=step,
                        )
                    )
                    memory.last_status = AgentStatus.RETRY
                    if (
                        decision.password_candidate
                        and decision.password_candidate in memory.candidate_passwords
                        and decision.password_candidate not in memory.rejected_candidates
                    ):
                        self._verify_candidate(
                            memory=memory,
                            candidate=decision.password_candidate,
                            step=step,
                            emit=emit,
                        )
                        if memory.verified_password is not None:
                            status = AgentStatus.SOLVED
                            break
                    if no_action_streak >= self._max_missing_actions:
                        memory.error_summary = "Der Agent konnte keinen neuen sicheren Schritt finden."
                        status = AgentStatus.NEEDS_INPUT
                        break
                    emit(
                        AgentStatus.RETRY,
                        {
                            "level": memory.level,
                            "attempt": step,
                            "max_attempts": config.max_steps,
                            "hypothesis": memory.last_hypothesis,
                            "last_command": None,
                            "output": decision.reason or "Kein Befehl vorgeschlagen.",
                            "exit_code": None,
                            "verification_status": memory.verification_status,
                        },
                    )
                    continue
                no_action_streak = 0

                is_valid, normalized = validate_command(command)
                if not is_valid:
                    memory.consecutive_failures += 1
                    memory.record_rejection(command, normalized)
                    memory.record_strategy(
                        StrategyRecord(
                            name="command_validation",
                            command=command,
                            outcome="rejected",
                            reason=normalized,
                            step=step,
                        )
                    )
                    memory.last_status = AgentStatus.RETRY
                    if memory.consecutive_failures >= self._max_consecutive_failures:
                        memory.error_summary = "Zu viele ungültige Befehlsvorschläge."
                        status = AgentStatus.NEEDS_INPUT
                        break
                    emit(
                        AgentStatus.RETRY,
                        {
                            "level": memory.level,
                            "phase": "command_rejected",
                            "attempt": step,
                            "max_attempts": config.max_steps,
                            "hypothesis": memory.last_hypothesis,
                            "last_command": command,
                            "output": f"Befehl {command!r} abgewiesen: {normalized}",
                            "reason": normalized,
                            "summary": "Der Vorschlag wurde vor jeder SSH-Ausführung durch die zentrale Befehlsrichtlinie abgelehnt.",
                            "exit_code": 126,
                            "verification_status": memory.verification_status,
                        },
                    )
                    continue

                memory.consecutive_failures = 0

                if memory.has_tried(normalized):
                    duplicate_streak += 1
                    duplicate_count = duplicate_streak
                    memory.duplicate_count = duplicate_count
                    memory.record_strategy(
                        StrategyRecord(
                            name="duplicate_command",
                            command=normalized,
                            outcome="rejected",
                            reason="Befehl wurde bereits ausgeführt.",
                            step=step,
                        )
                    )
                    if duplicate_streak >= self._max_duplicates:
                        memory.error_summary = "Der Agent schlägt wiederholt bereits ausgeführte Befehle vor."
                        status = AgentStatus.NEEDS_INPUT
                        break
                    emit(
                        AgentStatus.RETRY,
                        {
                            "level": memory.level,
                            "attempt": step,
                            "max_attempts": config.max_steps,
                            "hypothesis": memory.last_hypothesis,
                            "last_command": normalized,
                            "output": "Wiederholung verhindert. Bitte eine andere, informationsbringende Strategie wählen.",
                            "exit_code": 0,
                            "verification_status": memory.verification_status,
                        },
                    )
                    continue
                duplicate_streak = 0

                memory.last_status = AgentStatus.RUNNING
                emit(
                    AgentStatus.RUNNING,
                    {
                        "level": memory.level,
                        "phase": "command_ready",
                        "attempt": step,
                        "max_attempts": config.max_steps,
                        "hypothesis": memory.last_hypothesis,
                        "last_command": normalized,
                        "output": f"Führe aus: {normalized}",
                        "exit_code": None,
                        "verification_status": memory.verification_status,
                    },
                )

                # Ensure the connection is still usable. Reconnect once if needed.
                if not ssh.is_connected():
                    reconnect_failure = ssh.connect()
                    if reconnect_failure is not None:
                        if reconnect_failure.error_type == "authentication":
                            memory.error_summary = "Authentifizierung für das aktuelle Level fehlgeschlagen."
                            status = AgentStatus.NEEDS_INPUT
                            break
                        memory.error_summary = reconnect_failure.error_message or "SSH-Verbindung unterbrochen."
                        status = AgentStatus.ERROR
                        break

                if config.stop_requested():
                    memory.error_summary = "Ausführung durch den Benutzer angehalten."
                    status = AgentStatus.NEEDS_INPUT
                    break

                if config.command_approval is not None:
                    approved = config.command_approval(
                        normalized,
                        {
                            "level": memory.level,
                            "step": step,
                            "max_attempts": config.max_steps,
                            "hypothesis": decision.hypothesis,
                            "summary": decision.summary,
                            "strategy": decision.strategy,
                            "reason": decision.reason,
                            "expected_output": decision.expected_output,
                            "candidate_options": candidate_options,
                        },
                    )
                    selected_candidate = None
                    if isinstance(approved, str):
                        selected_candidate = next(
                            (
                                option for option in candidate_options
                                if option["command"] == approved
                            ),
                            None,
                        )
                        if selected_candidate is None:
                            memory.error_summary = "Die ausgewählte Lernmodus-Option war nicht freigegeben."
                            status = AgentStatus.NEEDS_INPUT
                            break
                        selected_valid, selected_normalized = validate_command(
                            selected_candidate["command"]
                        )
                        if not selected_valid or memory.has_tried(selected_normalized):
                            memory.error_summary = "Die ausgewählte Lernmodus-Option ist nicht mehr sicher ausführbar."
                            status = AgentStatus.NEEDS_INPUT
                            break
                        normalized = selected_normalized
                        decision.hypothesis = selected_candidate["hypothesis"]
                        decision.summary = selected_candidate["summary"]
                        decision.strategy = selected_candidate["strategy"]
                        decision.reason = selected_candidate["reason"]
                        decision.expected_output = selected_candidate["expected_output"]
                        memory.add_hypothesis(decision.hypothesis, decision.confidence)
                        memory.last_hypothesis = decision.hypothesis
                    elif not approved:
                        memory.error_summary = (
                            "Ausführung durch den Benutzer angehalten."
                            if config.stop_requested()
                            else "Der vorgeschlagene Befehl wurde nicht freigegeben."
                        )
                        memory.last_status = AgentStatus.NEEDS_INPUT
                        status = AgentStatus.NEEDS_INPUT
                        break

                result = ssh.execute(normalized, timeout=config.command_timeout)
                attempt = Attempt(
                    step=step,
                    command=normalized,
                    strategy=decision.strategy or "llm_strategy",
                    result=result,
                    hypothesis=decision.hypothesis,
                    started_at=time.monotonic() - result.duration,
                    finished_at=time.monotonic(),
                )
                memory.record_attempt(attempt)

                if result.error_type == "authentication":
                    memory.record_strategy(
                        StrategyRecord(
                            name="ssh_authentication",
                            command=normalized,
                            outcome="failed",
                            reason=result.error_message or "Authentifizierung fehlgeschlagen.",
                            step=step,
                        )
                    )
                    memory.error_summary = "Authentifizierung für das aktuelle Level fehlgeschlagen."
                    status = AgentStatus.NEEDS_INPUT
                    break

                if result.error_type in {"connection", "host_key", "unknown"}:
                    memory.record_strategy(
                        StrategyRecord(
                            name="ssh_connection",
                            command=normalized,
                            outcome="failed",
                            reason=result.error_message or result.error_type or "Verbindungsfehler.",
                            step=step,
                        )
                    )
                    memory.last_status = AgentStatus.ERROR
                    memory.error_summary = result.error_message or "SSH-Verbindungsfehler."
                    status = AgentStatus.ERROR
                    break

                if result.timed_out:
                    memory.record_strategy(
                        StrategyRecord(
                            name="command_timeout",
                            command=normalized,
                            outcome="failed",
                            reason="Befehl hat das Zeitlimit überschritten.",
                            step=step,
                        )
                    )
                    memory.last_status = AgentStatus.RETRY
                    emit(
                        AgentStatus.RETRY,
                        {
                            "level": memory.level,
                            "attempt": step,
                            "max_attempts": config.max_steps,
                            "hypothesis": memory.last_hypothesis,
                            "last_command": normalized,
                            "output": memory.last_output,
                            "exit_code": result.exit_code,
                            "verification_status": memory.verification_status,
                        },
                    )
                    continue

                if result.exit_code not in (None, 0):
                    memory.record_strategy(
                        StrategyRecord(
                            name="command_failed",
                            command=normalized,
                            outcome="failed",
                            reason=f"Exit-Code {result.exit_code}.",
                            step=step,
                        )
                    )
                    memory.last_status = AgentStatus.RETRY
                    emit(
                        AgentStatus.RETRY,
                        {
                            "level": memory.level,
                            "attempt": step,
                            "max_attempts": config.max_steps,
                            "hypothesis": memory.last_hypothesis,
                            "last_command": normalized,
                            "output": memory.last_output,
                            "exit_code": result.exit_code,
                            "verification_status": memory.verification_status,
                        },
                    )
                    continue

                # Extract candidates only from actual command output.
                candidate = self._extract_password(result.stdout + "\n" + result.stderr)
                if candidate:
                    memory.remember_candidate(candidate)
                    secrets = [config.password, *memory.candidate_passwords]

                # If the model named the same candidate, verify only that real one.
                if candidate is None and decision.password_candidate:
                    if decision.password_candidate in memory.candidate_passwords:
                        candidate = decision.password_candidate

                if candidate:
                    verification = self._verify_candidate(
                        memory=memory,
                        candidate=candidate,
                        step=step,
                        emit=emit,
                    )
                    if isinstance(verification, VerificationResult) and verification.success:
                        status = AgentStatus.SOLVED
                        break
                    # verification failed: continue, do not solve
                    continue

                # Successful inspection without a candidate advances the investigation.
                memory.last_status = AgentStatus.RUNNING
                emit(
                    AgentStatus.RUNNING,
                    {
                        "level": memory.level,
                        "attempt": step,
                        "max_attempts": config.max_steps,
                        "hypothesis": memory.last_hypothesis,
                        "last_command": normalized,
                        "output": memory.last_output,
                        "exit_code": result.exit_code,
                        "verification_status": memory.verification_status,
                    },
                )

            else:
                if status not in {
                    AgentStatus.SOLVED,
                    AgentStatus.NEEDS_INPUT,
                    AgentStatus.ERROR,
                }:
                    status = AgentStatus.MAX_ATTEMPTS
                    memory.error_summary = "Maximale Anzahl von Versuchen erreicht."

        except Exception as exc:  # pragma: no cover - defensive boundary
            status = AgentStatus.ERROR
            memory.error_summary = f"Unerwarteter Fehler: {type(exc).__name__}: {exc}"

        finally:
            try:
                ssh.close()
            except Exception:
                pass
            memory.finished_at = time.monotonic()
            memory.last_status = status

        summary = self._make_summary(status, memory)
        output = redact_secrets(memory.last_output or "", secrets)

        return AgentResult(
            status=status,
            level=memory.level,
            attempts_count=len(memory.attempts),
            summary=summary,
            password=memory.verified_password,
            duration=memory.finished_at - memory.started_at,
            memory=memory,
            last_command=memory.last_command,
            last_output=output,
            verification_status=memory.verification_status,
            error=memory.error_summary,
        )

    def _extract_password(self, text: str) -> str | None:
        matches = re.findall(r"(?<![A-Za-z0-9])[A-Za-z0-9]{32}(?![A-Za-z0-9])", text)
        return matches[-1] if matches else None

    def _verify_candidate(
        self,
        memory: AgentMemory,
        candidate: str,
        step: int,
        emit: Callable[[AgentStatus, dict[str, Any]], None],
    ) -> VerificationResult:
        memory.tried_candidates.append(candidate)
        try:
            verification = self.config.verifier(memory.level, candidate)
        except Exception as exc:
            verification = VerificationResult(
                success=False,
                reason=f"Verifikation konnte nicht ausgeführt werden: {type(exc).__name__}: {exc}",
                error_type="unknown",
            )

        if verification.success:
            verification_status = "verified"
        elif verification.error_type == "authentication":
            verification_status = "rejected"
        else:
            verification_status = "error"

        emit(
            AgentStatus.RETRY if not verification.success else AgentStatus.RUNNING,
            {
                "level": memory.level,
                "attempt": step,
                "max_attempts": self.config.max_steps,
                "hypothesis": memory.last_hypothesis,
                "last_command": "verification",
                "output": verification.reason,
                "exit_code": verification.exit_code,
                "verification_status": verification_status,
            },
        )

        if verification.success:
            memory.verification_status = "verified"
            memory.verified_password = candidate
            memory.record_strategy(
                StrategyRecord(
                    name="verification",
                    command=None,
                    outcome="success",
                    reason=verification.reason,
                    step=step,
                )
            )
        else:
            memory.verification_status = verification_status
            if verification.error_type == "authentication":
                memory.rejected_candidates.add(candidate)
            memory.record_strategy(
                StrategyRecord(
                    name="verification",
                    command=None,
                    outcome="failed" if verification.error_type not in {"authentication", None} else "rejected",
                    reason=verification.reason,
                    step=step,
                )
            )
        return verification

    def _make_summary(self, status: AgentStatus, memory: AgentMemory) -> str:
        if status == AgentStatus.SOLVED:
            return (
                f"Level {memory.level}: Passwort gefunden und durch Login am nächsten "
                f"Bandit-Level unabhängig verifiziert. Versuche: {len(memory.attempts)}."
            )
        if status == AgentStatus.MAX_ATTEMPTS:
            return (
                f"Level {memory.level}: Versuchslimit ({memory.max_attempts}) erreicht. "
                f"Verifikation: {memory.verification_status}."
            )
        if status == AgentStatus.NEEDS_INPUT:
            return (
                f"Level {memory.level}: Agent benötigt Eingabe oder einen Hinweis. "
                f"Grund: {memory.error_summary or 'kein Fortschritt'}."
            )
        if status == AgentStatus.ERROR:
            return (
                f"Level {memory.level}: Fehler während der Ausführung. "
                f"Grund: {memory.error_summary or 'unbekannter Fehler'}."
            )
        return (
            f"Level {memory.level}: Ausführung beendet mit Status {status.value}. "
            f"Verifikation: {memory.verification_status}."
        )
