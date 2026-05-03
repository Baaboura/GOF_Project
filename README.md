# Adversarial Cognitive Mesh (PHAGE)

> **Real-time AI-powered cybersecurity threat detection and response — browser extension + multi-agent backend.**

This project, **PHAGE (Proactive Heuristic Adversarial Guard Engine)**, was developed as part of the coursework for **Cybersecurity and Artificial Intelligence** at **Esprit School of Engineering**. It focuses on real-time anomaly detection using machine learning to protect users from cybersecurity threats directly in their browser.

🌐 **Live site:** [www.gof.tn](https://www.gof.tn)

---

## Overview

PHAGE is a multi-agent AI system that monitors web traffic in real time and automatically detects, simulates, and responds to cybersecurity threats. A Chrome browser extension connects to a local Python backend that runs a 6-layer agent pipeline — from threat detection to deception deployment and memory crystallization.

The system was designed and built as part of the **Cybersecurity and Artificial Intelligence** curriculum at **Esprit School of Engineering**, combining concepts from machine learning, network security, and autonomous AI agents.

**Keywords:** cybersecurity, anomaly-detection, artificial-intelligence, machine-learning, browser-extension, multi-agent-system, threat-detection, python, real-time-security

---

## Tech Stack

| Layer | Technology |
|---|---|
| **Backend** | Python, FastAPI, Uvicorn |
| **Machine Learning** | scikit-learn, logistic regression, threat DNA fingerprinting |
| **AI Agents** | Custom multi-agent architecture (Sentinel, Triage, Red, Blue, Deception, Memory) |
| **Frontend / Extension** | JavaScript, HTML, CSS (Chrome Extension Manifest V3) |
| **Test Site** | Django, SQLite |
| **Report Generation** | ReportLab (PDF) |
| **Real-time Communication** | WebSockets, REST API |
| **Tools** | psutil, watchdog, pydantic |

---

## Features

- **Real-time anomaly detection** using machine learning and behavioral heuristics.
- **6-layer multi-agent pipeline** — Sentinel → Triage → Red → Blue → Deception → Memory.
- **Automated threat response** — countermeasures deployed within seconds of detection.
- **Adversarial simulation** — Red Agent simulates the full attacker kill chain.
- **Deception layer** — honeypots and canary tokens deployed automatically.
- **Threat DNA memory** — crystallized fingerprints enable instant recognition of future similar attacks.
- **PDF incident reports** — downloadable security reports generated after each scan.
- **Localhost-only operation** — extension activates exclusively on local development sites.
- **Django test site** — built-in attack simulation pages for DDoS, SQL injection, XSS, CSRF, and malicious URLs.
- **Protects users from unknown cyber threats** through behavioral pattern recognition.

---

## Architecture

```
Chrome Extension (popup.js)
        │
        ▼
FastAPI Server — localhost:8765  (server.py)
        │
        ▼
┌─────────────────────────────────────┐
│         Agent Pipeline              │
│  1. Sentinel Mesh  — detection      │
│  2. Triage Agent   — analysis       │
│  3. Red Agent      — simulation     │
│  4. Blue Agent     — response       │
│  5. Deception Weaver — honeypots    │
│  6. Memory Crystal — DNA storage    │
└─────────────────────────────────────┘
        ▲
        │  (real attack events)
Django Test Site — localhost:8000
  PhageMiddleware detects SQL/XSS/DDoS/CSRF
```

---

## Getting Started

### Prerequisites

- Python 3.10+
- Google Chrome
- pip

### Installation

```bash
git clone https://github.com/<your-username>/extention_Test.git
cd extention_Test
pip install -r requirements.txt
```

### Run the backend server

```powershell
python server.py
```

Server starts at `http://localhost:8765`.

### Run the Django test site

```powershell
cd django_test_site
pip install -r requirements.txt
python manage.py runserver
```

Test site starts at `http://localhost:8000`.

### Load the Chrome extension

1. Open Chrome → `chrome://extensions/`
2. Enable **Developer mode**
3. Click **Load unpacked** → select the `extension/` folder
4. Navigate to `http://localhost:8000` — the extension activates automatically

---

## Attack Simulations (Test Site)

| Attack Type | URL | Description |
|---|---|---|
| DDoS | `/ddos/` | Fires 200 rapid requests to simulate volumetric flood |
| SQL Injection | `/sqli/` | Submits malicious SQL payloads via form |
| XSS | `/xss/` | Reflects injected `<script>` tags |
| CSRF | `/csrf/` | Forged POST request without CSRF token |
| Malicious URL | `/malicious-url/` | Pattern-matched phishing and payload URLs |
| Brute Force | `/login/` | Repeated failed login attempts |

---

## Project Structure

```
extention_Test/
├── agents/              # AI agent implementations
│   ├── sentinel_mesh.py
│   ├── triage_agent.py
│   ├── red_agent.py
│   ├── blue_agent.py
│   ├── deception_weaver.py
│   └── memory_crystallizer.py
├── core/                # Event bus, orchestrator, data models
├── services/            # ML training, prediction, storage
├── extension/           # Chrome extension (MV3)
│   ├── manifest.json
│   ├── background.js
│   ├── popup.js
│   └── popup.html
├── django_test_site/    # Local attack simulation site
│   ├── app/
│   │   ├── views.py     # DDoS, SQLi, XSS, CSRF, malicious URL views
│   │   └── templates/
│   └── phage_middleware.py
├── reports/             # PDF report generator
├── data/                # Threat memory, alerts
├── models/              # Trained ML models
└── server.py            # FastAPI backend entry point
```

---

## Course Information

**Course:** Cybersecurity and Artificial Intelligence
**Institution:** Esprit School of Engineering
**Project:** PHAGE — Proactive Heuristic Adversarial Guard Engine

---

## License

This project is developed for educational purposes as part of coursework at Esprit School of Engineering.
