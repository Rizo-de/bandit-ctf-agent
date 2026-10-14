from enum import Enum


class AgentStatus(str, Enum):
    """Controlled status values returned by the Bandit agent."""

    RUNNING = "RUNNING"
    RETRY = "RETRY"
    SOLVED = "SOLVED"
    NEEDS_INPUT = "NEEDS_INPUT"
    MAX_ATTEMPTS = "MAX_ATTEMPTS"
    ERROR = "ERROR"