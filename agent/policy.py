from __future__ import annotations

import shlex
from typing import Optional, Sequence

ALLOWED_COMMANDS = {
    "pwd", "ls", "cat", "file", "find", "grep", "strings", "head",
    "tail", "sort", "uniq", "wc", "du", "stat", "xxd", "od", "base64",
    "tr", "cut", "gzip", "bzip2", "xz", "man", "help", "cd", "whoami",
    "id", "date",
}

BLOCKED_TOKENS = (
    ";", "&&", "||", "|", ">", "<", "`", "$(", "${", "\n", "\r", "&",
)

DANGEROUS_FIND_OPTIONS = {"-exec", "-execdir", "-delete", "-ok", "-okdir"}
MAX_COMMAND_LENGTH = 500


def normalize_command(command: str) -> str:
    """Normalize whitespace so duplicate detection is stable."""
    return " ".join(str(command).split())


def _has_dangerous_find_option(parts: Sequence[str]) -> bool:
    return any(part in DANGEROUS_FIND_OPTIONS for part in parts[1:])


def _has_write_capable_compression(parts: Sequence[str]) -> bool:
    """gzip/bzip2/xz must emit to stdout to avoid modifying files."""
    program = parts[0].lower()
    if program not in {"gzip", "bzip2", "xz"}:
        return False
    stdout_to_stdout = False
    for arg in parts[1:]:
        if arg in {"-c", "--stdout", "--to-stdout"}:
            stdout_to_stdout = True
        elif arg.startswith("-") and not arg.startswith("--") and "c" in arg[1:]:
            stdout_to_stdout = True
    if stdout_to_stdout:
        return False

    query_flags = {"-l", "--list", "-t", "--test", "-h", "--help", "-V", "--version"}
    if query_flags.intersection(parts[1:]):
        return False
    return True


def _has_output_file_argument(program: str, parts: Sequence[str]) -> bool:
    args = parts[1:]
    if program == "base64":
        return any(arg == "-o" or arg.startswith("--output") for arg in args)
    if program in {"xxd", "od"}:
        positional = [arg for arg in args if not arg.startswith("-")]
        return len(positional) > 1
    return False


def _validate_options(program: str, args: Sequence[str]) -> bool:
    """Reject option forms that can change files, spawn tools, or escape scope."""
    # Long options which invoke external commands, write output, or alter state
    # are not needed for the Bandit discovery workflows supported here.
    forbidden = ("--output", "--reference", "--checkpoint", "--backup", "--suffix")
    if any(arg.startswith(forbidden) for arg in args):
        return False
    if program == "find":
        allowed_actions = {"-name", "-iname", "-type", "-size", "-user", "-group", "-perm", "-maxdepth", "-mindepth", "-ls", "-print", "-print0", "-inum", "-mtime", "-atime", "-ctime", "-newer", "-readable", "-writable", "-empty"}
        return all(not arg.startswith("-") or arg in allowed_actions or arg in {"!", "-o", "-a", "(" , ")"} for arg in args)
    if program in {"ls"}:
        return all(not arg.startswith("-") or arg in {"-a", "-A", "-l", "-h", "-R", "-t", "-r", "-S", "-d", "-F", "-1", "--all", "--almost-all", "--long", "--human-readable", "--recursive", "--directory"} for arg in args)
    if program in {"cat", "head", "tail", "grep", "strings", "file", "wc", "sort", "uniq", "du", "stat", "xxd", "od", "base64", "tr", "cut", "gzip", "bzip2", "xz", "pwd", "whoami", "id", "date", "cd", "man", "help"}:
        # Allow known read-only flags; reject command execution and output paths.
        allowed = {
            "cat": {"-n", "-b", "-s", "-A", "-v", "-E", "-T"},
            "head": {"-n", "-c", "-q", "-v"}, "tail": {"-n", "-c", "-q", "-v", "-f"},
            "grep": {"-i", "-n", "-v", "-r", "-R", "-l", "-L", "-w", "-x", "-E", "-F", "-e", "-m", "-A", "-B", "-C"},
            "strings": {"-a", "-n", "-t", "-e", "-f"}, "file": {"-b", "-i", "-L", "-z"},
            "wc": {"-l", "-w", "-c", "-m", "-L"}, "sort": {"-r", "-n", "-u", "-f", "-h", "-k", "-t", "-c"},
            "uniq": {"-c", "-d", "-u", "-i", "-f", "-s", "-w"}, "du": {"-a", "-h", "-s", "-d", "--max-depth"},
            "stat": {"-c", "--format", "-L"}, "xxd": {"-l", "-s", "-g", "-c", "-p", "-r"},
            "od": {"-A", "-t", "-N", "-j", "-x", "-c", "-b", "-d", "-o"},
            "base64": {"-d", "--decode", "-w", "--wrap"}, "tr": {"-d", "-s", "-c"}, "cut": {"-b", "-c", "-d", "-f", "-s"},
            "gzip": {"-c", "-d", "-k", "-l", "-t", "-v", "-1", "-9"}, "bzip2": {"-c", "-d", "-k", "-t", "-v", "-1", "-9"},
            "xz": {"-c", "-d", "-k", "-l", "-t", "-v", "-1", "-9"}, "pwd": {"-L", "-P"},
        }.get(program, set())
        i = 0
        takes_value = {"head": {"-n", "-c"}, "tail": {"-n", "-c"}, "grep": {"-e", "-m", "-A", "-B", "-C"}, "strings": {"-n", "-t", "-e"}, "sort": {"-k", "-t"}, "uniq": {"-f", "-s", "-w"}, "du": {"-d", "--max-depth"}, "stat": {"-c", "--format"}, "xxd": {"-l", "-s", "-g", "-c"}, "od": {"-A", "-t", "-N", "-j"}, "base64": {"-w", "--wrap"}, "cut": {"-b", "-c", "-d", "-f"}}
        while i < len(args):
            arg = args[i]
            if arg.startswith("-") and arg not in allowed and not any(arg.startswith(flag) and arg != flag for flag in allowed if len(flag) == 2 and flag.startswith("-")):
                return False
            if arg in takes_value.get(program, set()):
                i += 1
                if i >= len(args):
                    return False
            i += 1
    return True


def validate_command(command: str) -> tuple[bool, str]:
    """
    Validate and normalize a command.

    Returns (True, normalized_command) on success and (False, reason) otherwise.
    """
    if not isinstance(command, str):
        return False, "Befehl muss Text sein."

    command = command.strip()
    if not command:
        return False, "Leerer Befehl."
    if len(command) > MAX_COMMAND_LENGTH:
        return False, "Befehl ist zu lang."

    if any(token in command for token in BLOCKED_TOKENS):
        return False, "Shell-Verknüpfungen, Umleitungen oder Zeilenumbrüche sind gesperrt."

    try:
        parts = shlex.split(command, posix=True)
    except ValueError as exc:
        return False, f"Befehl konnte nicht gelesen werden: {exc}"

    if not parts:
        return False, "Leerer Befehl."
    if parts[0] not in ALLOWED_COMMANDS:
        return False, "Dieses Programm steht nicht auf der erlaubten Lesebefehls-Liste."
    if parts[0] != parts[0].lower():
        return False, "Programmnamen müssen kleingeschrieben sein."

    program = parts[0].lower()
    if program == "find" and _has_dangerous_find_option(parts):
        return False, "find mit ausführenden oder löschenden Optionen ist gesperrt."

    if _has_write_capable_compression(parts):
        return False, (
            "Kompressionstools müssen mit -c/--stdout ausgeben, "
            "um Dateien nicht zu verändern."
        )

    if _has_output_file_argument(program, parts):
        return False, "Ausgabe in Dateien ist nicht erlaubt."

    if not _validate_options(program, parts[1:]):
        return False, "Diese Option ist nicht für die freigegebenen Nur-Lese-Befehle zugelassen."

    return True, normalize_command(command)
