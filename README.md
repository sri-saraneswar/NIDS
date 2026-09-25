# NIDS — Real-Time Network Intrusion Detection Dashboard

A real-time Network Intrusion Detection System (NIDS) built with Python and Flask. It captures live network traffic, analyzes packets for suspicious activity, raises alerts, and displays everything on a web dashboard.


## Overview

This project monitors network traffic in real time, flags potentially malicious activity, logs alerts to a database, and visualizes live statistics through a Flask dashboard.

## Features

- **Live packet capture** — sniffs traffic directly from a network interface
- **Modular detection pipeline** — packets flow through capture → flow tracking → analysis → detection → alerting
- **Real-time alerting** — flags and stores suspicious events as they happen
- **Web dashboard** — Flask-based UI for live monitoring and stats
- **Session tracking & reporting** — summarizes each monitoring session and generates reports
- **Persistent storage** — saves session statistics and alerts to a database for later review

## Architecture

```
NIDS/
├── capture/       # Live packet capture (interface selection, start/stop)
├── flow/          # Network flow tracking/reassembly
├── analyzer/       # Packet/flow analysis logic
├── detection/       # Intrusion detection rules/engine
├── alert/          # Alert manager — raises & tracks alerts
├── session/         # Session lifecycle (start/stop, summaries)
├── state/          # Shared application state
├── database/         # DB init and statistics persistence
├── dashboard/        # Flask app + routes for the web UI
├── templates/        # HTML templates for the dashboard
├── static/          # CSS/JS/assets for the dashboard
├── reports/         # Generated session/attack reports
├── console/         # CLI / console output utilities
├── config.py         # App configuration (version, author, etc.)
├── app.py           # Main entry point — wires everything together
└── requirements.txt
```

**Flow:** `capture` sniffs raw packets → `flow`/`analyzer` process and extract features → `detection` evaluates them against rules → `alert` raises and records any hits → `dashboard` displays live stats, and `session`/`database`/`reports` persist and summarize the run.

## Tech Stack

- **Language:** Python
- **Web framework:** Flask
- **Packet capture:** Scapy and npcap
- **Database:** SQLite 
- **Frontend:** HTML/CSS/JS (Flask templates)

## Getting Started

### Prerequisites

- Python 3.x
- Npcap (Windows) / Scapy (Linux) for packet capture
- Administrator/root privileges (required to capture live traffic)

### Installation

```bash
git clone https://github.com/sri-saraneswar/NIDS.git
cd NIDS
pip install -r requirements.txt
```

### Running

```bash
python app.py
```

Then open **http://127.0.0.1:5000** in your browser.

On startup, the app initializes the database, lets you select a network interface to monitor, starts a capture session, and serves the live dashboard.


## Roadmap / Future Improvements

- [ ] Add automated tests for detection logic
- [ ] Add CI (GitHub Actions) for linting/testing
- [ ] Add configurable detection thresholds via config.py
- [ ] Containerize with Docker for easier setup

## Author

SRI SARAN ESWAR S S 

## License

`TODO: Add a LICENSE file (MIT recommended) and reference it here.`
