# Bandit CTF Lern-Agent

Eine Streamlit-App zum geführten Untersuchen der autorisierten OverTheWire-Bandit-Level. Der Agent zeigt seine Hypothesen und Befehle an; Befehle unterliegen einer Lesebefehls-Prüfung und können vor der Ausführung freigegeben werden. Ein Level gilt erst nach erfolgreichem SSH-Login beim nächsten Level als gelöst.

## Installation auf Kali Linux

Voraussetzungen: Kali Linux mit Python 3, `venv` und Git. Im Terminal:

```bash
sudo apt update
sudo apt install -y git gh python3 python3-venv python3-pip
gh auth login --hostname github.com --git-protocol https --web
gh auth status
gh repo clone Rizo-de/bandit-ctf-agent
cd bandit-ctf-agent
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m streamlit run app.py
```

Öffne anschließend die von Streamlit angezeigte lokale Adresse (standardmäßig `http://localhost:8501`) im Browser der Kali-VM. Das Terminal mit Streamlit muss geöffnet bleiben. Beenden mit `Ctrl+C`.

Wenn du die Seite von einem anderen Rechner im privaten VM-Netz öffnen möchtest, starte stattdessen mit:

```bash
python -m streamlit run app.py --server.address 0.0.0.0
```

Dann nutze im Browser `http://<KALI-VM-IP>:8501`. Öffne den Port nur in einem vertrauenswürdigen privaten Netz.

## KI konfigurieren

- **OpenRouter:** links „OpenRouter API“ wählen, API-Schlüssel und Modell-ID eintragen und mit „KI-Verbindung und Modell prüfen“ testen. Schlüssel nicht in Dateien eintragen oder committen.
- **Ollama:** links lokale Ollama-Option wählen. Wenn Ollama auf einem anderen Rechner läuft, muss die App dessen erreichbare Adresse verwenden.

Zum Starten eines Bandit-Levels Host `bandit.labs.overthewire.org`, Port `2220`, Benutzer und Passwort eintragen. Beim ersten SSH-Kontakt den Hostkey-Fingerprint anzeigen und nur bei erwartbarem OverTheWire-Erstkontakt vertrauen.

## Tests

```bash
python -m pip install pytest
python -m pytest -q
```

## Lokale Zugangsdaten

Verifizierte Level-Passwörter werden lokal als Klartextdatei gespeichert. Die App zeigt den tatsächlichen Pfad an. Schütze dein Betriebssystemkonto und teile die Datei nicht. `.env`-Dateien, virtuelle Umgebungen, Passwortdateien, SSH-Hostkey-Daten und Laufzeit-Arbeitsdateien sind in `.gitignore` ausgeschlossen.

## Umfang und Sicherheit

Der Agent ist für das OverTheWire-Bandit-Ziel auf Port 2220 eingeschränkt. Es gibt keine Garantie, dass ein LLM immer den richtigen nächsten Schritt findet. Prüfe die vorgeschlagenen Befehle und Ausgaben, bevor du sie freigibst. Verwende das Projekt nur mit Konten und Systemen, für die du autorisiert bist.
