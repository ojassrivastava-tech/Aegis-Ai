# AEGIS AI: Explainable Network Intrusion Detection and SOC Platform

AEGIS AI is a full-stack security operations (SOC) platform built around a machine
learning intrusion detector. It classifies network connections as **normal** or
**attack** with a Random Forest model, explains each detection with **SHAP**, maps
attacks to **MITRE ATT&CK** techniques, and can **block attackers automatically** at the
gateway. Everything streams to a live dashboard over WebSockets, and a built-in
**security copilot** lets analysts query and act on incidents in plain language.

> **Demo data:** traffic is simulated by replaying rows from the NSL-KDD dataset, and
> the source IPs and map locations are fictional. The project does not capture real
> network packets.

## Features

- **Attack detection:** Random Forest classifier (100 trees, max depth 15) trained on
  the 41 NSL-KDD features. Output is binary: Normal or Attack. The training script
  compares a Random Forest and a Decision Tree candidate.
- **Explainability:** SHAP `TreeExplainer` returns the top 5 features behind each
  detection, and a plain-English incident report is generated from them (template based,
  no external API needed).
- **MITRE ATT&CK mapping:** detected attacks are tagged with a technique (for example
  T1498 DoS flood, T1595 port scan, T1110 brute force, T1068 privilege escalation).
  This mapping is rule based, using the dataset's attack labels and the key features.
  It is not predicted by the model.
- **Active defense:** block or unblock source IPs from the dashboard. Blocked IPs are
  dropped at the gateway before the ML model runs. Optional **auto-defense** blocks
  detected attackers automatically, and an **emergency lockdown** mode drops all traffic.
- **Real-time dashboard:** Socket.IO live alert feed, statistics and charts (Chart.js),
  a Leaflet threat map with simulated source locations, a Three.js visual, and a
  history view with search, filters and CSV export.
- **Authentication and audit trail:** JWT login with bcrypt-hashed passwords and
  admin / analyst / viewer account roles. Sensitive actions are written to an audit log.
- **Persistence:** SQLite (Node's built-in `node:sqlite`) stores users, alerts, the
  blocklist and audit logs.
- **Security copilot:** a chat assistant in the dashboard with a built-in cybersecurity
  knowledge base and commands such as blocking an IP, unblocking, lockdown and incident
  briefings. It can optionally use a local LLM through Ollama or Google Gemini.
- **Traffic simulators:** a simulator built into the gateway, plus a command-line
  simulator (`simulate_traffic.py`) with a targeted attack demo.
- **Tests:** unit tests for the ML service and model selection (Python), and for the
  database layer and copilot (Node).

## Architecture

```
[Simulator / traffic source]
          |
          v
[Node.js gateway :4000]  --REST-->  [FastAPI ML service :8000]
  - REST API + Socket.IO              - Random Forest prediction
  - JWT auth, audit log               - SHAP explanation
  - SQLite storage                    - incident report + MITRE category
  - IP blocklist, auto-defense
  - security copilot
          |
          v
[Dashboard served by the gateway]
```

## Tech Stack

| Area | Technologies |
|------|--------------|
| Machine learning | Python, Scikit-learn, SHAP, Pandas, NumPy |
| ML service | FastAPI, Uvicorn |
| Gateway and backend | Node.js, Express, Socket.IO, JWT, bcrypt, SQLite (`node:sqlite`), Axios |
| Dashboard | HTML, CSS, JavaScript, Chart.js, Leaflet, Three.js |
| Deployment | Docker, Docker Compose, Render (`render.yaml`) |

## Project Structure

```
.
├── api/                    # FastAPI ML service (prediction, SHAP, report)
├── server/
│   ├── server.js           # Gateway: REST API, WebSockets, auth, defense logic
│   ├── db.js               # SQLite layer (users, alerts, blocklist, audit logs)
│   └── copilot.js          # Security copilot engine
├── dashboard/              # Dashboard (index.html) and bundled front-end libraries
├── src/
│   ├── preprocess.py       # Clean NSL-KDD data, encode features, create labels
│   ├── train_model.py      # Train and evaluate the model
│   ├── explain.py          # CLI demo of a SHAP explanation
│   └── generate_report.py  # Turn SHAP output into a plain-English report
├── models/                 # Trained model and feature list
├── data/                   # Processed NSL-KDD test set used by the simulators
├── tests/                  # Python and Node tests
├── simulate_traffic.py     # Command-line traffic simulator
├── docker-compose.yml      # ML service + gateway
├── Dockerfile              # Single-container image (used by render.yaml)
└── start.sh                # Starts the ML service and the gateway together
```

## Getting Started

The trained model (`models/nids_model.pkl`) and the processed test data are included,
so the project runs without downloading anything.

### Option 1: Docker Compose

```bash
docker compose up --build
```

Open **http://localhost:4000**.

### Option 2: Run locally

Requires Python 3.11+ and Node.js 22.5+ (24 recommended, because the gateway uses
`node:sqlite`).

```bash
# Terminal 1: ML service
pip install -r api/requirements.txt
uvicorn api.ml_service:app --port 8000

# Terminal 2: gateway and dashboard
cd server
npm install
npm start
```

Open **http://localhost:4000**.

### Generate traffic

Use the simulator controls in the dashboard, or run the command-line simulator in
another terminal:

```bash
pip install pandas requests
python simulate_traffic.py --continuous
python simulate_traffic.py --demo-attack     # 8 attack connections from one fictional IP
```

### Demo flow: attack, detect, block

Auto-Defense is **on** by default, so the first detected attack from an IP blocks that IP
automatically and later packets from it show as Blocked. To walk through the manual
flow, switch Auto-Defense off in the dashboard first.

1. Run `python simulate_traffic.py --demo-attack` (8 connections from one fictional IP).
2. Open an alert to see the SHAP-based explanation and the MITRE technique.
3. Block the source IP from the alert panel (with Auto-Defense on this has already happened).
4. Run the demo again. Connections from that IP are shown as **Blocked** and never
   reach the ML model.

## Configuration

| Variable | Purpose | Default |
|----------|---------|---------|
| `PORT` | Gateway port | `4000` |
| `ML_SERVICE_URL` | URL of the FastAPI service | `http://localhost:8000` |
| `JWT_SECRET` | Secret used to sign login tokens | built-in demo value |
| `GEMINI_API_KEY` | Enables the Gemini-powered copilot | not set |
| `OLLAMA_HOST` / `OLLAMA_MODEL` | Local LLM for the copilot | `http://localhost:11434` / `llama3.2` |

## Retraining the model

To retrain on the full NSL-KDD dataset, download it from
[Kaggle](https://www.kaggle.com/datasets/hassan06/nslkdd), place `KDDTrain+.txt` and
`KDDTest+.txt` in `data/`, then run:

```bash
pip install -r requirements.txt
python src/preprocess.py
python src/train_model.py     # prints accuracy, classification report, confusion matrix
```

## Tests

```bash
python -m unittest discover -s tests
node tests/test_server_copilot.js
```

## Demo Mode and Security Notes

This project is a demonstration platform and is not hardened for production use.

- On first visit the dashboard signs in automatically as the seeded demo `admin`
  account. Demo accounts (`admin`, `analyst`, `auditor`) are created on the first run.
- Change the seeded passwords and set a strong `JWT_SECRET` before exposing it anywhere.
- Account roles are stored in the token, but not every action is restricted by role yet.

## Limitations

- Binary classification only (Normal vs Attack). Attack type and MITRE technique come
  from rules, not from the model.
- Trained and evaluated on NSL-KDD, a benchmark dataset. Detecting real traffic would
  need feature extraction from live packets, which is not implemented.
- Traffic, source IPs and locations are simulated.

## Roadmap

- Multi-class model that predicts the attack type directly.
- Role-based access control enforced on every sensitive endpoint.
- Live packet capture and feature extraction.
- Proper model validation (hold-out set for model selection) and metric reporting.
