# AEGIS AI — Threat Intelligence & Active Defense

An explainable, full-stack Network Intrusion Detection System that detects
attacks in real time using Machine Learning, explains *why* each detection
was flagged (SHAP), generates plain-English incident reports, and can
actively block repeat offenders — all shown on a live 3D dashboard.

## Architecture

```
[simulate_traffic.py]  →  [Node.js API Gateway :4000]  →  [Python ML Service :8000]
    (simulates live          (REST API, stores alert          (model + SHAP +
     network traffic)         history, serves dashboard)       report generation)
                                      ↓
                              [Dashboard :4000]
                          (live charts + alert feed)
```

## Project Structure
```
nids-project/
├── data/                   # Dataset goes here
├── models/                 # Trained model gets saved here
├── src/
│   ├── preprocess.py       # Step 1: Clean & prepare data
│   ├── train_model.py      # Step 2: Train the ML model
│   ├── explain.py          # Step 3: Explain a prediction (SHAP) — CLI demo
│   └── generate_report.py  # Step 4: Human-readable incident report
├── api/
│   ├── ml_service.py       # FastAPI service — serves the model as an API
│   ├── requirements.txt
│   └── Dockerfile
├── server/
│   ├── server.js           # Node.js API Gateway — the piece your internship skills built
│   ├── package.json
│   └── Dockerfile
├── dashboard/
│   └── index.html          # Live monitoring dashboard
├── simulate_traffic.py     # Replays test data as "live" traffic, for demos
├── docker-compose.yml      # Runs everything together
└── README.md
```

## Part A: Build & Train the Model (do this first)

1. Download **NSL-KDD**: https://www.kaggle.com/datasets/hassan06/nslkdd
   Place `KDDTrain+.txt` and `KDDTest+.txt` into `data/`

2. Install core dependencies and train:
```bash
pip install -r requirements.txt
python src/preprocess.py
python src/train_model.py
python src/explain.py           # optional CLI demo of SHAP explanation
python src/generate_report.py   # optional CLI demo of report generation
```

This creates `models/nids_model.pkl`, which the API service uses.

## Part B: Run the Full System

### Option 1 — Docker (recommended for your demo/submission)

Once you have `models/nids_model.pkl` (from Part A):

```bash
docker compose up --build
```

Then open **http://localhost:4000** in your browser — that's your live dashboard.

In a **separate terminal** (not inside Docker), run the simulator to generate live traffic:
```bash
pip install pandas requests
python simulate_traffic.py --count 60 --delay 0.8
```

Watch the dashboard update in real time as attacks get detected and explained.

### Option 2 — Run without Docker (for development/debugging)

You need **3 terminals** open at once:

**Terminal 1 — ML Service (Python):**
```bash
pip install -r api/requirements.txt
uvicorn api.ml_service:app --reload --port 8000
```

**Terminal 2 — Backend (Node.js):**
```bash
cd server
npm install
npm start
```

**Terminal 3 — Simulator:**
```bash
python simulate_traffic.py --count 60 --delay 0.8
```

Then open **http://localhost:4000** for the dashboard.

## For Your College Demo: Attack → Detect → Block

This is the full live-demo script. It shows detection AND active defense —
not just passive alerts.

**Step 1 — Warm up with general traffic (optional, builds up the dashboard):**
```bash
python simulate_traffic.py --count 30 --delay 0.8
```

**Step 2 — Send a targeted attack from one IP:**
```bash
python simulate_traffic.py --demo-attack
```
This sends 8 attack connections all from the same fake IP (`203.0.113.7`).
Watch the dashboard flag them as **ATTACK** in real time.

**Step 3 — Explain it:**
Click any "ATTACK" row in the Live Alert Feed. The Incident Report panel opens,
showing the SHAP-based explanation (which features triggered the detection)
in plain English.

**Step 4 — Block the source:**
At the bottom of the Incident Report, click **"BLOCK SOURCE"**. The dashboard
confirms the IP has been added to the firewall blocklist, and the "Blocked
Sources" counter increases.

**Step 5 — Replay the same attack (the payoff moment):**
```bash
python simulate_traffic.py --demo-attack
```
This time, the dashboard instantly shows **BLOCKED** for every connection —
the system rejects them before they even reach the ML model, because the
source is already known-malicious.

**What to say out loud:** *"The first time, our AI model analyzed the traffic
and correctly flagged it as an attack, explaining exactly why. Once I block
that source, the system remembers it — so if the same attacker tries again,
AEGIS AI rejects them instantly at the gateway, without even needing to run
the model again. That's the difference between just detecting threats and
actively defending against them."*

## What Each Attack Type Means

| Category | What it is | Example |
|----------|-----------|---------|
| DoS | Denial of Service — flooding a target to make it unavailable | SYN flood |
| Probe | Scanning a network to find vulnerabilities | Port scanning |
| R2L | Remote-to-Local — unauthorized access from a remote machine | Password guessing |
| U2R | User-to-Root — a local user trying to gain admin/root access | Buffer overflow |

## Tech Stack Summary (for your CV/report)

- **Machine Learning:** Python, Scikit-learn (Random Forest), SHAP (explainability)
- **Backend API:** Python (FastAPI) for the ML microservice, Node.js (Express) as the API Gateway
- **Frontend:** HTML/CSS/JavaScript, Chart.js for live visualizations
- **Deployment:** Docker & Docker Compose (multi-container orchestration)
- **Architecture pattern:** Microservices (separate ML service + API gateway, communicating over REST)

## Possible Extensions (if you want to go further)
- Add a multi-class model (predict DoS/Probe/R2L/U2R specifically, not just Attack/Normal)
- Add authentication to the dashboard
- Persist alerts in a real database (MongoDB/PostgreSQL) instead of a JSON file
- Add email/Slack notifications when an attack is detected
- Deploy to a free-tier cloud service (Render/Railway) so it's live on the internet
