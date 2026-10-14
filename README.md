# Bandit CTF Lern-Agent

Eine lokal auf deiner Kali-VM laufende Streamlit-App zum geführten Untersuchen der autorisierten OverTheWire-Bandit-Level. Die App verbindet sich von deiner VM aus per verschlüsseltem SSH mit Bandit. Sie lehnt unbekannte oder geänderte SSH-Hostschlüssel ab und speichert einen neuen Schlüssel erst nach deiner ausdrücklichen Bestätigung.

## Voraussetzungen

- Kali Linux mit Internetzugang
- Python 3.10 bis 3.14 und Git
- Für die KI-Funktion entweder ein laufender Ollama-Dienst mit heruntergeladenem Modell oder ein OpenRouter-Konto mit API-Schlüssel

Führe Installationsbefehle in einem **Kali-Terminal** aus. Wenn ein Befehl einen Fehler meldet, stoppe dort und behebe ihn, bevor du fortfährst. Verwende `sudo` nur für APT-Pakete, niemals für `pip`.

## 1. Installation

### Systempakete

```bash
sudo apt update
sudo apt install -y git python3 python3-venv python3-pip
```

Prüfe die Python-Version:

```bash
python3 --version
```

### Repository laden

Das Repository ist öffentlich; `gh` und eine GitHub-Anmeldung sind zum Herunterladen nicht nötig. Klone es im Kali-Terminal:

```bash
cd ~/Downloads
git clone https://github.com/Rizo-de/bandit-ctf-agent.git
cd bandit-ctf-agent
```

Falls das Repository später privat wird, brauchst du Zugriff mit deinem GitHub-Konto. Mit installierter GitHub CLI kannst du dich ohne Token in der Befehlszeile über den Browser anmelden und danach HTTPS verwenden:

```bash
gh auth login --hostname github.com --git-protocol https --web
gh auth setup-git
git clone https://github.com/Rizo-de/bandit-ctf-agent.git
```

`gh` fehlt möglicherweise in deiner Kali-APT-Konfiguration; installiere es nur nach der offiziellen GitHub-Anleitung: [GitHub CLI installieren](https://github.com/cli/cli/blob/trunk/docs/install_linux.md). Alternativ kannst du einen bereits eingerichteten GitHub-SSH-Schlüssel verwenden. Gib niemals einen Token oder ein Passwort in die Clone-URL, den Quellcode oder eine eingecheckte Datei ein.

Falls der Ordner `~/Downloads/bandit-ctf-agent` bereits existiert, klone nicht erneut. Öffne stattdessen im Kali-Terminal den vorhandenen Ordner:

```bash
cd ~/Downloads/bandit-ctf-agent
```

### Virtuelle Umgebung und Python-Abhängigkeiten

Führe die folgenden Befehle im Projektordner `~/Downloads/bandit-ctf-agent` aus:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Nach der Aktivierung sollte `(.venv)` am Anfang der Terminal-Eingabezeile erscheinen. Die Abhängigkeiten werden ausschließlich in dieser virtuellen Umgebung installiert. Bei einem Fehler beim Erstellen von `.venv` prüfe, dass `python3-venv` installiert ist.

## 2. App starten

Im Kali-Terminal, im Projektordner:

```bash
cd ~/Downloads/bandit-ctf-agent
source .venv/bin/activate
python -m streamlit run app.py
```

Öffne die von Streamlit angezeigte Adresse, normalerweise `http://localhost:8501`, im Browser **innerhalb derselben Kali-VM**. Lass das Terminal geöffnet, solange du die App verwendest. Beende sie mit `Ctrl+C`.

Die App ist für die lokale Nutzung auf der Kali-VM gedacht. Binde sie nicht an `0.0.0.0`, wenn du sie nicht ausdrücklich in einem vertrauenswürdigen Netzwerk bereitstellen willst.

## 3. KI-Verbindung konfigurieren

Wähle links in der App eine der beiden Optionen:

- **Ollama (lokal):** Ollama muss separat installiert und gestartet sein; das Python-Paket in `requirements.txt` ist nur der Ollama-Client. Lade in Ollama eines der angebotenen Modelle herunter (`llama3`, `codellama` oder `mistral`). Verwende `http://localhost:11434`, wenn Ollama auf derselben Kali-VM läuft. Wenn Ollama auf einem anderen Rechner läuft, trage dessen aus Kali erreichbare Adresse ein. Installationshinweise stehen in der [offiziellen Ollama-Dokumentation](https://docs.ollama.com/).
- **OpenRouter API:** Trage den API-Schlüssel in das maskierte Schlüsselfeld und eine Modell-ID im Format `anbieter/modell` ein. Nutze **„KI-Verbindung und Modell prüfen“**. Der Schlüssel gehört nicht in den Quellcode, eine URL oder eine eingecheckte Datei. Prompts und Befehlsausgaben werden an OpenRouter gesendet; API-Nutzung kann Kosten verursachen.

### OpenRouter-Modelle auswählen

Die folgenden Beispiele wurden am **14. Oktober 2026** anhand der OpenRouter-Modellseiten geprüft. Verfügbarkeit, Preis, Limits und Modellversionen können sich ändern. Prüfe vor der Nutzung die jeweils aktuelle Modellseite und wähle dort eine verfügbare Variante:

| Zweck | Modell-ID | Hinweise |
|---|---|---|
| Kostenloser Einstieg | `cohere/north-mini-code:free` | Für Code- und Terminalaufgaben ausgelegt. Kostenfrei laut OpenRouter-Modellseite, aber kostenlose Anbieter können begrenzte Kapazität und Rate-Limits haben. |
| Mehr Leistung für schwierige Agentenschritte | `xiaomi/mimo-v2.5` | OpenRouter beschreibt es als leistungsfähiges agentisches Modell; die Modellseite nennt außerdem Unterstützung für strukturierte Ausgaben. Kostenpflichtig; die tatsächlichen Kosten hängen vom Anbieter ab. |
| Schnelle, leichtere Aufgaben | `openai/gpt-5.6-luna` | OpenRouter positioniert es für schnelle, kosteneffiziente und latenzempfindliche Aufgaben. |
| Aufwendige Programmier- und Agentenaufgaben | `xiaomi/mimo-v2.5-pro` | Xiaomis Flaggschiffmodell für komplexe agentische und Softwareentwicklungs-Aufgaben; Kostenpflichtig. |

Für diesen Bandit-Agenten ist `cohere/north-mini-code:free` ein guter Start ohne Modellkosten. Wenn Antworten wiederholt unvollständig sind, Limits erreicht werden oder der Agent schwach schlussfolgert, teste `xiaomi/mimo-v2.5` als nächsten Schritt. Ein größeres oder teureres Modell löst Rate-Limits nicht automatisch; prüfe dafür zusätzlich dein OpenRouter-Kontingent und die Anbieterverfügbarkeit.

OpenRouter-Links: [alle Modelle und aktuelle Filter](https://openrouter.ai/models), [kostenlose Modelle](https://openrouter.ai/collections/free-models), [Programmiermodelle](https://openrouter.ai/collections/programming), [North Mini Code](https://openrouter.ai/cohere/north-mini-code:free), [MiMo-V2.5](https://openrouter.ai/xiaomi/mimo-v2.5), [GPT-5.6 Luna](https://openrouter.ai/openai/gpt-5.6-luna), [MiMo-V2.5-Pro](https://openrouter.ai/xiaomi/mimo-v2.5-pro).

## 4. SSH-Hostschlüssel beim Erstkontakt bestätigen

Die Bandit-Verbindung verwendet normales verschlüsseltes SSH zu `bandit.labs.overthewire.org` auf Port `2220`. Die offizielle [OverTheWire-Bandit-Seite](https://overthewire.org/wargames/bandit/bandit0.html) nennt Host und Port, veröffentlicht aber keinen Hostschlüssel-Fingerprint. Die App installiert deshalb keinen Fingerprint vor und vertraut einem unbekannten Schlüssel nicht automatisch.

Führe den Erstkontakt in der App aus:

1. Prüfe, dass Host und Port `bandit.labs.overthewire.org` und `2220` lauten.
2. Klicke **„Bandit-Hostschlüssel-Fingerprint anzeigen“**.
3. Vergleiche den angezeigten Fingerprint über einen vertrauenswürdigen, unabhängigen Kanal. Ein Community-Write-up ist keine offizielle Bestätigung. Wenn du den Fingerprint nicht unabhängig bestätigen kannst, entscheide bewusst, ob du dem Erstkontakt (TOFU) vertraust; die offizielle Seite stellt keinen Vergleichs-Fingerprint bereit.
4. Nur wenn du dem angezeigten Schlüssel vertraust, klicke **„Angezeigten Hostschlüssel für Bandit speichern und vertrauen“**. Warte auf **„Hostschlüssel gespeichert“**.
5. Klicke **„Verbindung prüfen“**.

Der Schlüssel wird in `~/.ssh/known_hosts` des Benutzers gespeichert, unter dem der Streamlit-Prozess läuft. Starte die App und speichere den Schlüssel daher in derselben Kali-VM und mit demselben Benutzerkonto. Ein bereits gespeicherter, abweichender Hostschlüssel wird nicht automatisch gelöscht oder ersetzt; brich in diesem Fall ab und prüfe die Ursache.

Nach erfolgreicher Verbindung trägst du Bandit-Level und Passwort links ein. Die App speichert verifizierte Level-Passwörter lokal im Benutzerverzeichnis. Diese Datei enthält Klartextpasswörter und darf nicht geteilt oder eingecheckt werden.

## Prüfungen für Entwickler

Führe diese Befehle im Projektordner mit aktivierter virtueller Umgebung aus:

```bash
python -m pytest -q
```

## Sicherheit und Umfang

Die App ist für lokale Nutzung mit OverTheWire Bandit vorgesehen. Sie beschränkt SSH auf `bandit.labs.overthewire.org:2220`, prüft den Hostschlüssel und lässt vorgeschlagene Lesebefehle vor der Ausführung prüfen und freigeben. Prüfe die Befehle und Ausgaben trotzdem selbst. Verwende die App nur mit Konten und Systemen, für die du autorisiert bist.
