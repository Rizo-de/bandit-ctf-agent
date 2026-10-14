import re
import shlex
import threading
import time
import os
import socket
import struct

import ollama
import paramiko
import httpx
import streamlit as st

from agent import (
    AgentConfig,
    AgentStatus,
    BanditAgent,
)
from agent.llm import OllamaLLMClient, get_ollama_content, redact_secrets
from agent.llm import OpenRouterLLMClient
from agent.collaboration import build_chat_prompt, chat_answer
from agent.policy import validate_command as policy_validate_command
from agent.ssh import BanditSSH
from agent.host_keys import fetch_bandit_host_key, host_key_fingerprint, save_bandit_host_key
from agent.password_store import load_passwords, password_store_path, save_passwords
from agent.verifier import BanditPasswordVerifier

st.set_page_config(page_title="Bandit CTF Agent", layout="wide")
st.title("🛡️ OverTheWire Bandit – Lern-Agent")
st.caption(
    "Der Agent untersucht die aktuelle Stufe, führt geprüfte Lesebefehle aus und nutzt die Ausgabe für den nächsten Schritt. "
    "Passwörter werden erst nach unabhängiger SSH-Verifikation als gelöst markiert."
)

for key, default in {
    "terminal_log": "Noch nicht verbunden. Zugangsdaten links eintragen.",
    "bandit_passwords": {},
    "agent_commands_by_user": {},
    "agent_running": False,
    "agent_status": "Bereit",
    "agent_thread": None,
    "agent_report": {},
    "agent_log": [],
    "agent_stop": {"value": False},
    "agent_approval": None,
    "ssh_status": "Nicht getestet",
    "bandit_host_key_candidate": None,
    "bandit_host_key_fingerprint": "",
    "chat_history_by_user": {},
    "agent_hints_by_user": {},
    "learning_mode": False,
    "learning_solution_revealed": False,
}.items():
    if key not in st.session_state:
        st.session_state[key] = default

if not st.session_state.get("password_store_loaded"):
    st.session_state.bandit_passwords.update(load_passwords())
    st.session_state.password_store_loaded = True

PASSWORD_STORE_PATH = password_store_path()


def persist_passwords(passwords):
    try:
        saved_path = save_passwords(passwords)
        st.session_state.password_store_path = str(saved_path)
        st.session_state.password_store_error = ""
        return saved_path
    except OSError as exc:
        st.session_state.password_store_error = f"{type(exc).__name__}: {exc}"
        return None


def mask_secret(text):
    if text is None:
        return ""
    return re.sub(r"(?<![A-Za-z0-9])[A-Za-z0-9]{32}(?![A-Za-z0-9])", "[REDACTED]", str(text))


def create_ollama_client(host):
    # Model inference can be slow, but an unreachable server should fail quickly.
    timeout = httpx.Timeout(180.0, connect=4.0)
    return ollama.Client(host=host.strip(), timeout=timeout)


def discover_ollama_urls():
    """Return likely Windows-host addresses visible from a WSL app process."""
    hosts = ["host.docker.internal"]
    try:
        with open("/proc/net/route", encoding="utf-8") as routes:
            for line in routes.readlines()[1:]:
                fields = line.split()
                if len(fields) > 2 and fields[1] == "00000000":
                    gateway = socket.inet_ntoa(struct.pack("<L", int(fields[2], 16)))
                    hosts.append(gateway)
                    break
    except (OSError, ValueError, struct.error):
        pass
    try:
        with open("/etc/resolv.conf", encoding="utf-8") as resolv:
            for line in resolv:
                fields = line.split()
                if len(fields) == 2 and fields[0] == "nameserver":
                    hosts.append(fields[1])
    except OSError:
        pass

    urls = []
    for host in hosts:
        try:
            resolved = socket.gethostbyname(host)
        except OSError:
            resolved = host
        if resolved not in {"127.0.0.1", "::1"}:
            url = f"http://{resolved}:11434"
            if url not in urls:
                urls.append(url)
    return urls


st.sidebar.header("🔐 SSH-Zugang")
ssh_host = st.sidebar.text_input("Host", "bandit.labs.overthewire.org")
ssh_port = st.sidebar.number_input("Port", min_value=1, max_value=65535, value=2220, step=1)
ssh_user = st.sidebar.text_input("Bandit-Level / Benutzer", "bandit0")
level_match = re.fullmatch(r"bandit(\d+)", ssh_user.strip(), flags=re.IGNORECASE)
if level_match and int(level_match.group(1)) > 0:
    old_passwords = re.findall(
        r"The password you are looking for:\s*([A-Za-z0-9]{32})",
        st.session_state.terminal_log,
    )
    if old_passwords and ssh_user not in st.session_state.bandit_passwords:
        st.session_state.bandit_passwords[ssh_user] = old_passwords[-1]
password_key = f"password_{ssh_user}"
saved_password = st.session_state.bandit_passwords.get(ssh_user, "")
if saved_password and not st.session_state.get(password_key):
    st.session_state[password_key] = saved_password
ssh_password = st.sidebar.text_input("Passwort für dieses Level", type="password", key=password_key)
llm_provider = st.sidebar.selectbox("KI-Verbindung", ["Ollama (lokal)", "OpenRouter API"])
local_model = None
openrouter_api_key = ""
openrouter_model = ""
if llm_provider == "Ollama (lokal)":
    local_model = st.sidebar.selectbox("Lokales Ollama-Modell", ["codellama", "llama3", "mistral"], index=1)
    active_model = local_model
else:
    if "openrouter_api_key_input" not in st.session_state:
        st.session_state.openrouter_api_key_input = os.environ.get("OPENROUTER_API_KEY", "")
    if "openrouter_model_input" not in st.session_state:
        st.session_state.openrouter_model_input = os.environ.get("OPENROUTER_MODEL", "")
    openrouter_api_key = st.sidebar.text_input(
        "OpenRouter API-Schlüssel", type="password", key="openrouter_api_key_input"
    )
    openrouter_model = st.sidebar.text_input(
        "OpenRouter Modell-ID", key="openrouter_model_input",
        placeholder="Anbieter/Modell (z. B. aus OpenRouter Models)",
    )
    active_model = openrouter_model.strip()
    st.sidebar.warning("Bei OpenRouter werden Prompt und Bandit-Befehlsausgaben an einen Cloud-Anbieter gesendet. API-Nutzung kann kostenpflichtig sein.")
if "ollama_url_input" not in st.session_state:
    st.session_state.ollama_url_input = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
if llm_provider == "Ollama (lokal)" and st.sidebar.button("🧭 Windows-Ollama in WSL suchen"):
    candidates = discover_ollama_urls()
    found_url = None
    last_error = "Keine Kandidaten gefunden."
    for candidate_url in candidates:
        try:
            create_ollama_client(candidate_url).list()
            found_url = candidate_url
            break
        except Exception as exc:
            last_error = f"{type(exc).__name__}: {exc}"
    if found_url:
        st.session_state.ollama_url_input = found_url
        st.session_state.ollama_autodetect_message = f"Ollama wurde unter {found_url} gefunden."
    else:
        st.session_state.ollama_autodetect_message = (
            f"Kein Ollama unter den WSL-Hostadressen erreichbar ({', '.join(candidates) or 'keine'}). "
            f"Letzter Fehler: {last_error}"
        )
ollama_url = st.session_state.ollama_url_input
if llm_provider == "Ollama (lokal)":
    ollama_url = st.sidebar.text_input(
        "Ollama-Server-URL",
        key="ollama_url_input",
        help="Adresse des Ollama-Dienstes aus Sicht dieser App. In WSL ist localhost je nach Netzmodus nicht immer Windows.",
    )
    if st.session_state.get("ollama_autodetect_message"):
        st.sidebar.info(st.session_state.ollama_autodetect_message)
max_steps = st.sidebar.slider("Maximale Schritte pro Lauf", 3, 30, 12)
max_seconds = st.sidebar.slider("Zeitlimit (Sekunden)", 60, 600, 300, step=30)
learning_mode = st.sidebar.checkbox(
    "Lernmodus: bis zu 5 sichere Hypothesen vergleichen",
    key="learning_mode",
    help="Erzeugt bis zu fünf getrennte KI-Vorschläge pro Schritt und kann bis zu fünf LLM-Aufrufe kosten. Es werden nur geprüfte Befehle zur Freigabe angeboten.",
)
if learning_mode and not st.session_state.get("_previous_learning_mode", False):
    st.session_state.learning_solution_revealed = False
st.session_state["_previous_learning_mode"] = learning_mode
if learning_mode:
    st.sidebar.checkbox(
        "Lösung / gespeicherte Passwörter einblenden",
        key="learning_solution_revealed",
        help="Zeigt Passwörter erst nach deiner ausdrücklichen Zustimmung.",
    )
st.sidebar.caption("Bei langsamen lokalen Modellen großzügiger setzen; die Laufzeit zeigt die Ollama-Wartezeit live an.")

ALLOWED = {"pwd", "ls", "cat", "file", "find", "grep", "strings", "head", "tail", "sort", "uniq", "wc", "du", "stat", "xxd", "od", "base64", "tr", "cut", "gzip", "bzip2", "xz", "man", "help", "cd", "whoami", "id", "date"}
BLOCKED = (";", "&&", "||", "|", ">", "<", "`", "$(", "${")


def validate_command(command):
    ok, detail = policy_validate_command(command)
    if not ok:
        return False, detail
    return True, detail


def run_ssh_command(command):
    if not authorized_target():
        return "GESPERRT: Nur bandit.labs.overthewire.org:2220 und Bandit-Levelkonten sind zugelassen.", 126
    if not ssh_password:
        return "FEHLER: Bitte das Passwort für dieses Level eingeben.", 1
    allowed, detail = validate_command(command)
    if not allowed:
        return f"GESPERRT: {detail}", 126
    ssh = BanditSSH(
        ssh_host,
        int(ssh_port),
        ssh_user,
        ssh_password,
        connect_timeout=8,
        command_timeout=15,
    )
    failure = ssh.connect()
    if failure is not None:
        ssh.close()
        return f"SSH-Fehler: {failure.error_type}: {failure.error_message}", 1
    result = ssh.execute(detail, timeout=15)
    ssh.close()
    if result.error_type and result.error_type != "timeout":
        return f"SSH-Fehler: {result.error_type}: {result.error_message}", 1
    output = result.stdout
    if result.stderr.strip():
        output += ("\n" if output else "") + "[Fehlerausgabe] " + result.stderr.strip()
    if result.timed_out:
        output += "\n[Timeout] " + (result.error_message or "")
    return output.strip() or "(keine Ausgabe)", result.exit_code if result.exit_code is not None else 1


def authorized_target():
    return (
        ssh_host.strip().lower() == "bandit.labs.overthewire.org"
        and int(ssh_port) == 2220
        and re.fullmatch(r"bandit\d+", ssh_user.strip(), flags=re.IGNORECASE) is not None
    )


def parse_command(answer):
    answer = re.sub(r"```(?:bash|sh|shell)?", "", answer, flags=re.IGNORECASE).replace("```", "")
    for line in answer.splitlines():
        match = re.match(r"^\s*(?:COMMAND|Befehl)\s*:\s*(.+?)\s*$", line, flags=re.IGNORECASE)
        if match:
            return match.group(1).strip().strip("`").strip()
    lines = [line.strip().strip("`").strip() for line in answer.splitlines() if line.strip()]
    if len(lines) == 1 and not re.match(r"^(SOLVED|STUCK)\b", lines[0], flags=re.IGNORECASE):
        return lines[0]
    return ""


def extract_password(output):
    matches = re.findall(r"(?<![A-Za-z0-9])[A-Za-z0-9]{32}(?![A-Za-z0-9])", output)
    return matches[-1] if matches else None


def next_level(username):
    match = re.fullmatch(r"bandit(\d+)", username.strip(), flags=re.IGNORECASE)
    return f"bandit{int(match.group(1)) + 1}" if match else "das nächste Bandit-Level"


def summarize_report(report, level):
    status = report.get("status", "Bereit")
    lines = [
        f"Status: {status}",
        f"Level: {level}",
        f"Hypothese: {report.get('hypothesis') or '(noch keine)'}",
        f"Befehl: {report.get('last_command') or '(keiner)'}",
        f"Exit-Code: {report.get('exit_code', '')}",
        f"Versuch: {report.get('attempt', 0)}/{report.get('max_attempts', max_steps)}",
        f"Verifikation: {report.get('verification_status', 'nicht geprüft')}",
    ]
    return "\n".join(lines)


def run_agent_worker(config, report, log, stop_flag):
    def callback(status, details):
        report["status"] = getattr(status, "value", str(status))
        report["phase"] = details.get("phase", report.get("phase", ""))
        report["level"] = details.get("level", report.get("level"))
        report["hypothesis"] = details.get("hypothesis", report.get("hypothesis"))
        report["last_command"] = details.get("last_command", report.get("last_command"))
        raw_output = details.get("output", "")
        report["output"] = mask_secret(raw_output)
        report["attempt"] = details.get("attempt", report.get("attempt", 0))
        report["max_attempts"] = details.get("max_attempts", report.get("max_attempts", config.max_steps))
        report["exit_code"] = details.get("exit_code", report.get("exit_code"))
        report["verification_status"] = details.get("verification_status", report.get("verification_status"))
        if "reason" in details:
            report["reason"] = mask_secret(str(details.get("reason") or ""))
        if "summary" in details:
            report["decision_summary"] = mask_secret(str(details.get("summary") or ""))
        if "expected_output" in details:
            report["expected_output"] = mask_secret(str(details.get("expected_output") or ""))
        if "candidate_options" in details:
            report["candidate_options"] = details["candidate_options"]
        if raw_output:
            first_line = mask_secret(str(raw_output).strip().splitlines()[0] if str(raw_output).strip() else "")
            log.append(f"[{report.get('attempt', 0)}] {details.get('last_command') or ''} -> {first_line}")
        if phase == "decision_ready":
            log.append(f"[Hypothese] {mask_secret(str(details.get('hypothesis') or ''))}")
            if details.get("reason"):
                log.append(f"[Begründung] {mask_secret(str(details['reason']))}")
            if details.get("expected_output"):
                log.append(f"[Erwartet] {mask_secret(str(details['expected_output']))}")

    try:
        result = BanditAgent(config).run()
        report["result"] = result
        known_secrets = [config.password]
        if result.memory is not None:
            known_secrets.extend(result.memory.candidate_passwords)
        report["status"] = getattr(result.status, "value", str(result.status))
        report["hypothesis"] = (
            result.memory.last_hypothesis if result.memory is not None else report.get("hypothesis")
        )
        report["last_command"] = result.last_command
        report["output"] = mask_secret(redact_secrets(result.last_output, known_secrets))
        report["verification_status"] = result.verification_status
        report["error"] = mask_secret(redact_secrets(result.error or "", known_secrets))
        report["diagnosis"] = report["error"] or result.summary
        if result.status == AgentStatus.SOLVED:
            log.append("[Agent] Level als gelöst und verifiziert gemeldet.")
        elif result.status == AgentStatus.MAX_ATTEMPTS:
            log.append("[Agent] Versuchslimit erreicht.")
        elif result.status == AgentStatus.NEEDS_INPUT:
            log.append("[Agent] Benutzereingabe erforderlich.")
        elif result.status == AgentStatus.ERROR:
            log.append(f"[Agent] Fehler: {report['error'] or 'unbekannt'}")
    except Exception as exc:
        report["status"] = "ERROR"
        report["error"] = mask_secret(redact_secrets(f"{type(exc).__name__}: {exc}", [config.password]))
        report["diagnosis"] = report["error"]
        log.append(f"[Agent] Unerwarteter Fehler: {report['error']}")


def wait_for_command_approval(command, details, report, log, stop_flag, approval_state, timeout_seconds):
    """Publish a proposed command and wait a bounded time for explicit approval."""
    if approval_state.get("approve_all"):
        report.update(
            {
                "status": "RUNNING",
                "phase": "command_execute",
                "diagnosis": "Laufweite Freigabe aktiv; geprüfter Befehl wird ausgeführt",
                "awaiting_approval": False,
                "proposed_command": command,
                "command_hypothesis": details.get("hypothesis", ""),
                "command_summary": details.get("summary", ""),
                "command_strategy": details.get("strategy", ""),
                "command_reason": details.get("reason", ""),
                "expected_output": details.get("expected_output", ""),
                "candidate_options": details.get("candidate_options", []),
                "attempt": details.get("step", report.get("attempt", 0)),
                "max_attempts": details.get("max_attempts", report.get("max_attempts")),
            }
        )
        log.append(f"[{time.strftime('%H:%M:%S')}] [Lauf-Freigabe {details.get('step', '')}] $ {command}")
        return True

    event = approval_state["event"]
    approval_state["decision"] = None
    approval_state["selected_command"] = command
    event.clear()
    report.update(
        {
            "status": "WAITING_APPROVAL",
            "phase": "waiting_approval",
            "diagnosis": "Befehl wartet auf deine Freigabe oder deinen eigenen Lösungsversuch",
            "awaiting_approval": True,
            "proposed_command": command,
            "command_hypothesis": details.get("hypothesis", ""),
            "command_summary": details.get("summary", ""),
            "command_strategy": details.get("strategy", ""),
            "command_reason": details.get("reason", ""),
            "expected_output": details.get("expected_output", ""),
            "candidate_options": details.get("candidate_options", []),
            "attempt": details.get("step", report.get("attempt", 0)),
            "max_attempts": details.get("max_attempts", report.get("max_attempts")),
        }
    )
    log.append(f"[{time.strftime('%H:%M:%S')}] [Vorschau {details.get('step', '')}] $ {command}")
    deadline = time.monotonic() + max(1, timeout_seconds)
    while time.monotonic() < deadline:
        if stop_flag.get("value"):
            report["awaiting_approval"] = False
            return False
        if event.wait(timeout=min(0.25, max(0.01, deadline - time.monotonic()))):
            approved = approval_state.get("decision") is True
            report["awaiting_approval"] = False
            report["status"] = "RUNNING" if approved else "NEEDS_INPUT"
            report["phase"] = "command_execute" if approved else "user_solve"
            report["diagnosis"] = "Genehmigter Befehl wird ausgeführt" if approved else "Agent pausiert; du kannst selbst weiterlösen"
            log.append("[Freigabe] Befehl wird ausgeführt." if approved else "[Agent] Befehl nicht ausgeführt; du löst selbst weiter.")
            if not approved:
                return False
            if details.get("candidate_options"):
                return approval_state.get("selected_command") or command
            return True
    report["awaiting_approval"] = False
    report["status"] = "NEEDS_INPUT"
    report["approval_message"] = "Freigabezeit abgelaufen; der Befehl wurde nicht ausgeführt."
    return False


st.subheader("Verbindung")
st.subheader("🔐 Erster SSH-Kontakt (Bandit-Hostschlüssel)")
st.caption(
    "Beim ersten SSH-Kontakt ist der Hostschlüssel noch unbekannt. "
    "Lass dir den Fingerprint anzeigen und vertraue ihm nur, wenn du den Erstkontakt erwartest. "
    "Danach wird der Schlüssel in known_hosts dieser Laufzeit gespeichert; spätere Änderungen werden weiter abgewiesen."
)
if st.button("🔎 Bandit-Hostschlüssel-Fingerprint anzeigen"):
    if not authorized_target():
        st.error("Der Hostschlüssel kann nur für bandit.labs.overthewire.org:2220 geprüft werden.")
    else:
        try:
            candidate_key = fetch_bandit_host_key(ssh_host.strip(), int(ssh_port), timeout=8)
            st.session_state.bandit_host_key_candidate = candidate_key
            st.session_state.bandit_host_key_fingerprint = host_key_fingerprint(candidate_key)
        except Exception as exc:
            st.session_state.bandit_host_key_candidate = None
            st.session_state.bandit_host_key_fingerprint = ""
            st.error(f"SSH-Hostschlüssel konnte nicht abgerufen werden: {type(exc).__name__}: {exc}")

candidate_host_key = st.session_state.bandit_host_key_candidate
if candidate_host_key is not None:
    st.warning(
        "Erstkontakt-Vertrauen (TOFU): Der Fingerprint wird vom aktuell erreichten Server angezeigt, "
        "aber nicht unabhängig von OverTheWire bestätigt. Prüfe ihn über einen vertrauenswürdigen Kanal, "
        "bevor du ihn speicherst."
    )
    st.code(
        f"{candidate_host_key.get_name()} {st.session_state.bandit_host_key_fingerprint}",
        language="text",
    )
    if st.button("✅ Angezeigten Hostschlüssel für Bandit speichern und vertrauen"):
        try:
            path = save_bandit_host_key(ssh_host.strip(), int(ssh_port), candidate_host_key)
            st.session_state.bandit_host_key_candidate = None
            st.session_state.bandit_host_key_fingerprint = ""
            st.success(f"Hostschlüssel gespeichert: {path}. Du kannst jetzt den Verbindungstest erneut ausführen.")
        except Exception as exc:
            st.error(f"Hostschlüssel wurde nicht gespeichert: {type(exc).__name__}: {exc}")

left, right = st.columns(2)
with left:
    if st.button("🔌 Verbindung prüfen"):
        output, code = run_ssh_command("pwd")
        st.session_state.terminal_log += f"\n\n[Verbindungstest] Exit-Code: {code}\n{mask_secret(output)}"
        st.session_state.ssh_status = "Verbunden" if code == 0 else "Fehler"
        if code == 0:
            st.success("SSH-Verbindung funktioniert.")
        else:
            st.error(mask_secret(output))
with right:
    st.metric("SSH-Status", st.session_state.ssh_status)
    st.metric("Agentenstatus", st.session_state.agent_status)

st.subheader("🧠 KI-Verbindung")
if st.button("🔎 KI-Verbindung und Modell prüfen"):
    try:
        if llm_provider == "Ollama (lokal)":
            model_response = create_ollama_client(ollama_url).list()
            available_models = sorted({
                getattr(model, "model", None) or getattr(model, "name", "")
                for model in getattr(model_response, "models", [])
            } - {""})
            model_available = any(
                name == local_model or name.startswith(local_model + ":")
                for name in available_models
            )
            st.session_state.ollama_status = {
                "provider": "Ollama (lokal)", "reachable": True,
                "models": available_models, "selected_model_available": model_available,
            }
        else:
            if not openrouter_api_key.strip():
                raise ValueError("Bitte zuerst den OpenRouter API-Schlüssel eingeben.")
            if not openrouter_model.strip():
                raise ValueError("Bitte eine Modell-ID im Format Anbieter/Modell eingeben.")
            model_info = OpenRouterLLMClient(openrouter_api_key, openrouter_model).check_model()
            st.session_state.ollama_status = {
                "provider": "OpenRouter API", "reachable": True,
                "selected_model_available": bool(model_info),
                "model_name": model_info.get("name", openrouter_model),
            }
    except Exception as exc:
        st.session_state.ollama_status = {
            "provider": llm_provider, "reachable": False,
            "error": f"{type(exc).__name__}: {exc}",
        }

llm_status = st.session_state.get("ollama_status")
if llm_status and llm_status.get("provider") == llm_provider:
    if not llm_status.get("reachable"):
        st.error(f"{llm_status.get('provider', llm_provider)} nicht erreichbar oder Konfiguration ungültig: {llm_status.get('error', 'unbekannt')}")
    elif llm_status.get("selected_model_available") and llm_status.get("provider") == "OpenRouter API":
        st.success(f"OpenRouter erreichbar; Modell bestätigt: {llm_status.get('model_name')}.")
    elif llm_status.get("selected_model_available"):
        st.success(f"Ollama erreichbar; Modell {local_model} ist vorhanden.")
    elif llm_status.get("provider") == "Ollama (lokal)":
        st.warning(
            f"Ollama ist erreichbar, aber {local_model} wurde nicht gefunden. "
            f"Verfügbare Modelle: {', '.join(llm_status.get('models', [])) or '(keine)'}."
        )

st.subheader("🤖 Agent starten")
st.info(
    "Ein Schritt = ein geprüfter Lesebefehl. Zeit- und Schrittlimits verhindern Endlosschleifen. "
    "Verifizierte Passwörter werden lokal gespeichert; den Dateipfad findest du beim Ergebnis und unter den gespeicherten Passwörtern."
)

report = st.session_state.agent_report or {}
log_lines = st.session_state.agent_log or []
is_running = bool(st.session_state.agent_running)

start_col, stop_col = st.columns(2)
with start_col:
    start_clicked = st.button(
        "🚀 Level autonom untersuchen",
        type="primary",
        disabled=is_running,
    )
with stop_col:
    stop_clicked = st.button("⏹ Stoppen", disabled=not is_running)

if stop_clicked:
    st.session_state.agent_stop["value"] = True
    approval = st.session_state.agent_approval
    if approval is not None:
        approval["event"].set()
    st.rerun()

if start_clicked and not is_running:
    if not authorized_target():
        st.error("Der Agent ist auf bandit.labs.overthewire.org:2220 und Bandit-Levelkonten beschränkt.")
        st.stop()
    if not ssh_password:
        st.error("Bitte zuerst das Passwort für dieses Bandit-Level eingeben.")
        st.stop()
    if llm_provider == "OpenRouter API":
        if not openrouter_api_key.strip():
            st.error("Bitte zuerst den OpenRouter API-Schlüssel links eingeben.")
            st.stop()
        if not openrouter_model.strip() or "/" not in openrouter_model:
            st.error("Bitte eine OpenRouter Modell-ID im Format Anbieter/Modell eingeben.")
            st.stop()
        llm_client = OpenRouterLLMClient(openrouter_api_key, openrouter_model)
    else:
        llm_client = OllamaLLMClient(
            model=local_model,
            options={"temperature": 0, "num_predict": 192, "num_ctx": 2048},
            chat_func=create_ollama_client(ollama_url).chat,
        )
    st.session_state.agent_stop["value"] = False
    approval_state = {"event": threading.Event(), "decision": None, "approve_all": False}
    st.session_state.agent_approval = approval_state
    st.session_state.agent_log = []
    st.session_state.agent_report = {
        "status": "RUNNING",
        "level": ssh_user,
        "hypothesis": "",
        "last_command": "",
        "output": "",
        "attempt": 0,
        "max_attempts": max_steps,
        "started_at": time.time(),
        "exit_code": None,
        "verification_status": "not_verified",
        "error": "",
    }
    config = AgentConfig(
        host=ssh_host,
        port=int(ssh_port),
        username=ssh_user,
        password=ssh_password,
        model=active_model,
        max_steps=max_steps,
        max_seconds=max_seconds,
        command_timeout=15,
        connect_timeout=8,
        llm=llm_client,
        ssh_factory=None,
        verifier=BanditPasswordVerifier(
            ssh_host,
            int(ssh_port),
            connect_timeout=8,
            command_timeout=8,
        ),
        stop_requested=lambda: worker_stop["value"],
        status_callback=None,
        terminal_log=st.session_state.terminal_log,
        user_hints=st.session_state.agent_hints_by_user.setdefault(ssh_user, []),
        learning_mode=learning_mode,
    )
    worker_report = st.session_state.agent_report
    worker_log = st.session_state.agent_log
    worker_stop = st.session_state.agent_stop
    config.status_callback = None

    def _cb(status, details):
        status_name = getattr(status, "value", str(status))
        worker_report["status"] = status_name
        phase = details.get("phase")
        if phase:
            worker_report["phase"] = phase
            worker_report["phase_started_at"] = time.time()
            phase_labels = {
                "ssh_connect": "SSH-Verbindung wird aufgebaut",
                "llm_wait": "Warte auf Ollama / LLM-Antwort",
                "decision_ready": "LLM-Vorschlag ausgewertet",
                "command_ready": "Befehl vorbereitet; Freigabe folgt",
                "command_rejected": "Vorschlag durch die Befehlsrichtlinie abgelehnt",
                "llm_error": "Ollama/LLM-Fehler; Wiederholungsversuch oder Abbruch wird ausgewertet",
                "llm_rate_limited": "OpenRouter-Limit erreicht; Agent wartet auf Kontingent oder Guthaben",
            }
            label = phase_labels.get(phase, phase)
            worker_report["diagnosis"] = label
            worker_log.append(f"[{time.strftime('%H:%M:%S')}] [Diagnose] {label} (Versuch {details.get('attempt', 0)}/{details.get('max_attempts', max_steps)})")
        worker_report["level"] = details.get("level", worker_report.get("level"))
        worker_report["hypothesis"] = details.get("hypothesis", worker_report.get("hypothesis"))
        worker_report["last_command"] = details.get("last_command", worker_report.get("last_command"))
        raw_output = details.get("output", "")
        worker_report["output"] = mask_secret(raw_output)
        worker_report["attempt"] = details.get("attempt", worker_report.get("attempt", 0))
        worker_report["max_attempts"] = details.get(
            "max_attempts", worker_report.get("max_attempts", max_steps)
        )
        worker_report["exit_code"] = details.get("exit_code", worker_report.get("exit_code"))
        worker_report["verification_status"] = details.get(
            "verification_status", worker_report.get("verification_status")
        )
        if "candidate_options" in details:
            worker_report["candidate_options"] = details["candidate_options"]
        if details.get("output") and not details.get("phase"):
            worker_report["diagnosis"] = mask_secret(str(details["output"]).strip().splitlines()[0][:240])
        if details.get("llm_duration") is not None:
            worker_report["llm_duration"] = round(float(details["llm_duration"]), 1)
            worker_log.append(f"[{time.strftime('%H:%M:%S')}] [LLM-Dauer] {worker_report['llm_duration']:.1f} s")
        if raw_output:
            first_line = mask_secret(
                str(raw_output).strip().splitlines()[0] if str(raw_output).strip() else ""
            )
            worker_log.append(f"[{time.strftime('%H:%M:%S')}] [{worker_report.get('attempt', 0)}] {details.get('last_command') or 'LLM'} -> {first_line}")
        if details.get("reason"):
            worker_report["reason"] = mask_secret(str(details["reason"]))
        if details.get("expected_output"):
            worker_report["expected_output"] = mask_secret(str(details["expected_output"]))
        if phase == "decision_ready":
            worker_log.append(
                f"[Hypothese] {mask_secret(str(details.get('hypothesis') or ''))}"
            )
            if details.get("reason"):
                worker_log.append(f"[Begründung] {mask_secret(str(details['reason']))}")
            if details.get("expected_output"):
                worker_log.append(f"[Erwartet] {mask_secret(str(details['expected_output']))}")

    config.status_callback = _cb
    config.command_approval = lambda command, details: wait_for_command_approval(
        command,
        details,
        worker_report,
        worker_log,
        worker_stop,
        approval_state,
        max_seconds,
    )
    thread = threading.Thread(
        target=run_agent_worker,
        args=(config, worker_report, worker_log, worker_stop),
        daemon=True,
    )
    st.session_state.agent_thread = thread
    st.session_state.agent_running = True
    thread.start()
    st.rerun()

if is_running or st.session_state.agent_thread is not None:
    if is_running:
        report = st.session_state.agent_report or {}
        thread = st.session_state.agent_thread
        st.markdown("### Agent-Diagnose")
        phase_labels = {
            "ssh_connect": "🔌 SSH-Verbindung wird aufgebaut …",
            "llm_wait": "🧠 Ollama/LLM verarbeitet gerade die Level-Informationen …",
            "decision_ready": "✅ LLM-Vorschlag liegt vor; Sicherheitsprüfung läuft …",
            "command_ready": "⌛ Befehl ist vorbereitet …",
            "command_rejected": "⛔ Befehl wurde abgelehnt und nicht ausgeführt …",
            "llm_rate_limited": "⚠️ OpenRouter-Limit erreicht. Bitte warte und prüfe Limits/Guthaben im OpenRouter-Konto.",
        "llm_error": "⚠️ Ollama/LLM-Fehler; der Agent wertet einen Wiederholungsversuch aus …",
        "waiting_approval": "🧩 Befehl wartet auf deine Freigabe oder deinen eigenen Lösungsversuch …",
        "command_execute": "▶ Genehmigter Befehl wird ausgeführt …",
        "user_solve": "🧩 Agent pausiert; du kannst selbst weiterlösen.",
        }
        st.info(phase_labels.get(report.get("phase"), report.get("diagnosis") or report.get("status", "Agent läuft")))
        if report.get("phase") == "llm_wait" and report.get("phase_started_at"):
            waiting_seconds = max(0, int(time.time() - report["phase_started_at"]))
            st.caption(f"Ollama denkt seit {waiting_seconds} s · letzte Antwort: {report.get('llm_duration', 'noch keine')} s")
        c1, c2, c3 = st.columns(3)
        with c1:
            st.metric("Level", report.get("level", ssh_user))
            st.metric("Versuch", f"{report.get('attempt', 0)}/{report.get('max_attempts', max_steps)}")
        with c2:
            st.metric("Status", report.get("status", "RUNNING"))
            st.metric("Verifikation", report.get("verification_status", "nicht geprüft"))
        with c3:
            st.metric("Letzter Exit-Code", report.get("exit_code", ""))
            st.metric("Letzter Befehl", report.get("last_command", "") or "-")
        st.text_area("Aktuelle Hypothese", report.get("hypothesis", ""), height=90, disabled=True)
        if report.get("reason"):
            st.write(f"**Begründung:** {report['reason']}")
        if report.get("decision_summary"):
            st.info(f"**Abgleich mit bisherigen Beobachtungen:** {report['decision_summary']}")
        if report.get("proposed_command"):
            st.markdown("### Command-Panel · LLM-Vorschlag")
            st.caption("Das zeigt die kurze Begründung des Modells, keine verborgene Gedankenkette.")
            st.write(report.get("command_hypothesis") or report.get("command_summary") or "Keine Hypothese geliefert.")
            if report.get("command_strategy"):
                st.write(f"**Strategie:** {report['command_strategy']}")
            if report.get("command_reason"):
                st.write(f"**Warum dieser Befehl:** {report['command_reason']}")
            st.code(report["proposed_command"], language="bash")
            if report.get("expected_output"):
                st.caption(f"Erwartete Ausgabe: {report['expected_output']}")
            if report.get("candidate_options") and learning_mode:
                with st.expander("Lernmodus: geprüfte Hypothesen für diesen Schritt", expanded=True):
                    for option in report["candidate_options"]:
                        st.markdown(f"**Option {option['number']}:** {option['hypothesis'] or 'Hypothese fehlt'}")
                        st.caption(f"Befehl: {option['command']} · Erwartet: {option['expected_output'] or 'keine Angabe'}")
                        if option.get("reason"):
                            st.caption(f"Begründung: {option['reason']}")
            if report.get("awaiting_approval"):
                options = report.get("candidate_options", []) if learning_mode else []
                if options:
                    st.warning("Noch kein Befehl wurde ausgeführt. Wähle eine geprüfte Option und gib sie ausdrücklich frei.")
                    selected_number = st.radio(
                        "Welche Hypothese soll geprüft werden?",
                        range(len(options)),
                        format_func=lambda index: f"Option {options[index]['number']}: {options[index]['hypothesis']} · {options[index]['command']}",
                        key=f"learning_choice_{report.get('attempt', 0)}",
                    )
                    approve_col, solve_col = st.columns(2)
                    with approve_col:
                        if st.button("▶ Ausgewählte Option ausführen", key="approve_learning_command", type="primary"):
                            approval = st.session_state.agent_approval
                            approval["selected_command"] = options[selected_number]["command"]
                            approval["decision"] = True
                            approval["event"].set()
                            st.rerun()
                    with solve_col:
                        if st.button("🧩 Ich probiere selbst – Agent stoppen", key="decline_learning_command"):
                            approval = st.session_state.agent_approval
                            approval["decision"] = False
                            approval["event"].set()
                            st.rerun()
                else:
                    st.warning("Der Befehl wurde noch nicht ausgeführt. Du kannst nur diesen Befehl oder den gesamten aktuellen Lauf freigeben.")
                    approve_col, approve_all_col, solve_col = st.columns(3)
                    with approve_col:
                        if st.button("▶ Diesen Befehl ausführen", key="approve_llm_command", type="primary"):
                            approval = st.session_state.agent_approval
                            approval["decision"] = True
                            approval["event"].set()
                            st.rerun()
                    with approve_all_col:
                        if st.button("▶▶ Diesen Lauf freigeben", key="approve_all_llm_commands"):
                            approval = st.session_state.agent_approval
                            approval["approve_all"] = True
                            approval["decision"] = True
                            approval["event"].set()
                            st.rerun()
                    with solve_col:
                        if st.button("🧩 Ich probiere selbst – Agent stoppen", key="decline_llm_command"):
                            approval = st.session_state.agent_approval
                            approval["decision"] = False
                            approval["event"].set()
                            st.rerun()
            elif report.get("approval_message"):
                st.info(report["approval_message"])
        st.text_area("Tatsächliche Befehlsausgabe", report.get("output", ""), height=160, disabled=True)
        if report.get("exit_code") is not None:
            st.caption(f"Tatsächlicher Exit-Code: {report['exit_code']}")
        st.markdown("### Live-Konsole · neueste Ereignisse zuerst")
        st.code("\n".join((st.session_state.agent_log or [])[-120:]), language="text")

        if thread is not None and not thread.is_alive():
            st.session_state.agent_running = False
            thread = st.session_state.agent_thread
            st.session_state.agent_thread = None
            result = (st.session_state.agent_report or {}).get("result")
            if result is not None and result.status == AgentStatus.SOLVED and result.password:
                st.session_state.bandit_passwords[next_level(ssh_user)] = result.password
                saved_password_path = persist_passwords(st.session_state.bandit_passwords)
                st.session_state.terminal_log += (
                    f"\n\n[Agent] Level {ssh_user} gelöst und verifiziert. "
                    f"Versuche: {result.attempts_count}. Passwort: [REDACTED]"
                )
                st.session_state.agent_status = "Level gelöst"
                st.success(
                    f"🎉 Passwort für {ssh_user} gefunden und verifiziert. Nächstes Level: {next_level(ssh_user)}."
                )
                if saved_password_path:
                    st.caption(f"Verifiziertes Passwort gespeichert unter: {saved_password_path}")
                st.balloons()
            elif result is not None:
                safe_error = mask_secret(redact_secrets(
                    result.error or "",
                    [ssh_password, *(result.memory.candidate_passwords if result.memory else [])],
                ))
                st.session_state.terminal_log += (
                    f"\n\n[Agent] Level {ssh_user}: Status {result.status.value}. "
                    f"Versuche: {result.attempts_count}. Verifikation: {result.verification_status}."
                    + (f" Grund: {safe_error}" if safe_error else "")
                )
                st.session_state.agent_status = result.status.value
                if result.status == AgentStatus.MAX_ATTEMPTS:
                    st.warning("Maximale Schrittzahl erreicht. Prüfe den Verlauf oder starte erneut.")
                elif result.status == AgentStatus.NEEDS_INPUT:
                    st.warning("Der Agent benötigt eine Eingabe oder einen Hinweis.")
                elif result.status == AgentStatus.ERROR:
                    st.error(safe_error or "Unbekannter Fehler während der Agentenausführung.")
            st.rerun()
        else:
            time.sleep(0.5)
            st.rerun()
    else:
        pass

if not st.session_state.agent_running and st.session_state.agent_thread is None:
    report = st.session_state.agent_report or {}
    if report:
        st.markdown("### Letzter Agentenlauf")
        st.metric("Status", report.get("status", "Bereit"))
        if (
            report.get("status") == AgentStatus.SOLVED.value
            and report.get("verification_status") == "verified"
        ):
            next_user = next_level(report.get("level", ssh_user))
            next_password = st.session_state.bandit_passwords.get(next_user)
            st.success(f"Level {report.get('level', ssh_user)} ist gelöst und verifiziert.")
            if next_password:
                saved_password_path = persist_passwords(st.session_state.bandit_passwords)
                if not learning_mode or st.session_state.learning_solution_revealed:
                    st.markdown(f"### Zugang für {next_user}")
                    st.code(f"Benutzer: {next_user}\nPasswort: {next_password}", language="text")
                else:
                    st.info("Die bestätigte Lösung ist im Lernmodus ausgeblendet. Du kannst sie links ausdrücklich einblenden.")
                if saved_password_path:
                    st.caption(f"Gespeichert unter: {saved_password_path}")
        if st.session_state.get("password_store_error"):
            st.warning(f"Passwort ist in dieser Sitzung sichtbar, konnte aber nicht auf Datei gespeichert werden: {st.session_state.password_store_error}")
        st.info(report.get("diagnosis") or report.get("error") or "Lauf beendet.")
        if report.get("error") and not (
            report.get("status") == AgentStatus.SOLVED.value
            and report.get("verification_status") == "verified"
        ):
            st.error(report["error"])
        st.text_area("Hypothese", report.get("hypothesis", ""), height=90, disabled=True)
        if report.get("reason"):
            st.write(f"**Begründung:** {report['reason']}")
        if report.get("decision_summary"):
            st.info(f"**Abgleich mit bisherigen Beobachtungen:** {report['decision_summary']}")
        if report.get("expected_output"):
            st.caption(f"**Erwartete Ausgabe:** {report['expected_output']}")
        st.text_area("Ausgabe", report.get("output", ""), height=140, disabled=True)
        st.markdown("### Agent-Konsole · letzter Lauf")
        st.code("\n".join((st.session_state.agent_log or [])[-120:]) or "Noch keine Ereignisse.", language="text")

st.subheader("💬 Gemeinsam mit der KI lösen")
st.caption("Deine Hinweise bleiben für dieses Level in der Sitzung erhalten. Chat-Vorschläge werden angezeigt, aber nie automatisch ausgeführt.")
level_chat = st.session_state.chat_history_by_user.setdefault(ssh_user, [])
for chat_message in level_chat:
    with st.chat_message(chat_message["role"]):
        st.markdown(chat_message["content"])

chat_text = st.chat_input("Frage stellen oder einen Hinweis zum aktuellen Level geben")
if chat_text:
    chat_secrets = [ssh_password, *st.session_state.bandit_passwords.values()]
    safe_chat_text = mask_secret(redact_secrets(chat_text, chat_secrets))
    level_chat.append({"role": "user", "content": safe_chat_text})
    hints = st.session_state.agent_hints_by_user.setdefault(ssh_user, [])
    hints.append(safe_chat_text)
    del hints[:-15]
    with st.chat_message("user"):
        st.markdown(safe_chat_text)
    try:
        if llm_provider == "OpenRouter API":
            chat_client = OpenRouterLLMClient(openrouter_api_key, openrouter_model)
        else:
            chat_client = OllamaLLMClient(
                model=local_model,
                options={"temperature": 0, "num_predict": 192, "num_ctx": 2048},
                chat_func=create_ollama_client(ollama_url).chat,
            )
        chat_prompt = build_chat_prompt(
            level=ssh_user,
            goal=f"Finde und verifiziere das Passwort für {ssh_user} durch autorisierte Level-Untersuchung.",
            terminal_log=(
                st.session_state.terminal_log
                + "\n\nLetzte Agentenereignisse:\n"
                + "\n".join(st.session_state.agent_log[-60:])
            ),
            agent_report=st.session_state.agent_report or {},
            hints=hints,
            chat_history=level_chat,
            secrets=chat_secrets,
        )
        chat_decision = chat_client.decide(chat_prompt)
        command_ok = True
        if chat_decision.command:
            command_ok, _ = validate_command(chat_decision.command)
        answer = mask_secret(redact_secrets(chat_answer(chat_decision, command_ok), chat_secrets))
    except Exception as exc:
        answer = f"Die KI konnte gerade nicht antworten ({type(exc).__name__}). Prüfe die bestehende KI-Verbindung und versuche es erneut."
    level_chat.append({"role": "assistant", "content": answer})
    with st.chat_message("assistant"):
        st.markdown(answer)
    st.rerun()

st.subheader("✍️ Manueller Lesebefehl")
manual_command = st.text_input("Erlaubter Befehl", placeholder="zum Beispiel: ls -la")
if st.button("Befehl prüfen und ausführen"):
    valid, detail = validate_command(manual_command)
    if not valid:
        st.error(detail)
    else:
        output, code = run_ssh_command(detail)
        previous_commands = list(st.session_state.agent_commands_by_user.get(ssh_user, []))
        previous_commands.append(detail)
        st.session_state.agent_commands_by_user[ssh_user] = previous_commands[-30:]
        st.session_state.terminal_log += f"\n\n[Manuell] $ {detail}\nExit-Code: {code}\n{mask_secret(output)}"
        password = extract_password(output)
        if password:
            st.info("Ein Passwortkandidat wurde in der Ausgabe erkannt. Er gilt erst nach separater SSH-Verifikation als bestätigt.")
        else:
            st.success("Ausgabe steht im Verlauf.")

st.subheader("🖥️ Terminal-Verlauf")
st.text_area("Beobachtungen und Befehle", st.session_state.terminal_log, height=400, disabled=True)
with st.expander("Gespeicherte Level-Passwörter"):
    st.caption(f"Passwort-Datei: {st.session_state.get('password_store_path', PASSWORD_STORE_PATH)}")
    st.caption("Die lokale Datei enthält Passwörter im Klartext. Schütze dein Windows-/WSL-Benutzerkonto.")
    if st.session_state.bandit_passwords:
        if not learning_mode or st.session_state.learning_solution_revealed:
            for username, password in sorted(st.session_state.bandit_passwords.items()):
                st.markdown(f"**{username}**")
                st.code(password, language="text")
        else:
            st.info("Passwörter sind im Lernmodus ausgeblendet. Du kannst sie links ausdrücklich einblenden.")
        if st.button("Gespeicherte Level-Passwörter löschen"):
            st.session_state.bandit_passwords.clear()
            persist_passwords({})
            st.rerun()
    else:
        st.write("Noch keine Level-Passwörter gefunden.")
