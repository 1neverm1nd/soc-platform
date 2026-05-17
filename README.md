# SOC Platform — Security Operations Center

A full-stack Security Operations Center platform with ML-based threat detection, built as a diploma project at AITU.

## Features

- **ML Threat Detection** — XGBoost + RandomForest + ExtraTrees ensemble, 10 network flow classes, 15 text log classes
- **Real-time Incidents** — Server-Sent Events push, analyst workflow (open → investigating → resolved)
- **MITRE ATT&CK** — 19 mapped techniques, direct links to attack.mitre.org
- **Analytics** — Time-series charts, attack distribution, hourly heatmap
- **Network Graph** — Source → destination IP topology visualization
- **Geo Map** — Threat origin by country with severity overlay
- **IP Blocklist** — Manual IP blocking with reason tracking
- **Alert Rules** — Condition-based auto-triage (threshold, regex, rate)
- **Playbooks** — Automated response workflows per attack type
- **Notifications** — Real-time in-app alerts with unread badge
- **AI Analysis** — Gemini-powered incident summaries with fallback rule engine
- **Threat Intel** — AbuseIPDB integration for IP reputation scoring

---

## Stack

| Layer | Tech |
|-------|------|
| Frontend | React 18, TypeScript, Vite, Tailwind CSS, tRPC client, Recharts |
| Backend | Node.js, Express, tRPC, Drizzle ORM |
| Database | MySQL |
| ML | Python 3, scikit-learn, XGBoost, LightGBM (SHAP), joblib |
| Auth | JWT (RS256), bcryptjs |

---

## Prerequisites

- Node.js >= 18
- Python >= 3.10
- MySQL 8.x running locally
- (Optional) Gemini API key for AI analysis
- (Optional) AbuseIPDB key for threat intel

---

## Installation

### 1. Clone & install dependencies

```bash
git clone https://github.com/1neverm1nd/soc-platform.git
cd soc-platform

# Backend
cd backend
npm install

# Frontend
cd ../frontend
npm install
```

### 2. Environment variables

Create `backend/.env`:

```env
DATABASE_URL=mysql://root:password@localhost:3306/soc_platform
JWT_SECRET=your-super-secret-jwt-key-change-this
PORT=3001

# Optional
GEMINI_API_KEY=your-gemini-api-key
ABUSEIPDB_KEY=your-abuseipdb-api-key
```

Create `frontend/.env`:

```env
VITE_API_URL=http://localhost:3001
```

### 3. Database setup

```bash
cd backend
npm run db:push   # creates tables via Drizzle
```

Default users are seeded automatically on first start:
- `admin` / `admin123` — full access
- `analyst` / `analyst123` — analyst role

---

## ML Model Setup

### Train the text classifier (15 classes)

```bash
cd backend/ml
python generate_training_data.py   # generates training_data.jsonl
python train_model.py              # trains text classifier → model.pkl
```

### Train the flow classifier (UNSW-NB15, 10 classes)

Download the UNSW-NB15 dataset CSV files and place them in `backend/ml/data/`.

```bash
python train_flow_model_v5.py      # trains ensemble → flow_model_v5.pkl
```

Expected accuracy: ~75–76% (10-class, UNSW-NB15 test set)

---

## Running

### Development

```bash
# Terminal 1 — backend
cd backend
npm run dev

# Terminal 2 — frontend
cd frontend
npm run dev
```

Open [http://localhost:5173](http://localhost:5173)

### Production build

```bash
cd frontend
npm run build        # outputs to dist/

cd backend
npm run build        # compiles TypeScript
npm start
```

---

## ML Architecture

```
Input log text
    │
    ├─► Python predict.py
    │       ├─ Text model (TF-IDF + LogisticRegression)  — 15 classes
    │       ├─ Flow model (XGB x2 + RF x3 + ET x1)       — 10 classes
    │       ├─ Isolation Forest anomaly score
    │       ├─ SHAP explanation (top features)
    │       └─ Confidence threshold = 0.38 (below → "normal")
    │
    └─► Regex fallback (20 patterns, no Python required)
```

### Attack classes

| Text model | Flow model (UNSW-NB15) |
|-----------|----------------------|
| normal, brute-force, sql-injection, phishing, malware | normal, ddos, port-scanning |
| ransomware, lateral-movement, command-and-control | fuzzing, network-analysis, backdoor |
| cryptomining, ddos, data-exfiltration | shellcode, worm, vulnerability-exploit |
| privilege-escalation, unauthorized-access, vulnerability-exploit | unauthorized-access |

---

## Project Structure

```
soc-platform/
├── backend/
│   ├── src/
│   │   ├── routers/          # tRPC routers (incidents, auth, rules, ...)
│   │   ├── services/         # ML classifier, threat intel, SSE, playbooks
│   │   └── db/               # Drizzle schema + migrations
│   └── ml/
│       ├── predict.py            # Unified prediction entry point
│       ├── train_model.py        # Text classifier training
│       ├── train_flow_model_v5.py # Flow ensemble training
│       └── generate_training_data.py
├── frontend/
│   └── src/
│       ├── pages/            # All page components
│       ├── components/       # Shared UI + AttackSimulator
│       └── lib/              # tRPC client, auth, utils
└── README.md
```

---

## API Endpoints

All API calls use tRPC at `/trpc`. REST endpoints:

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Health check |
| GET | `/events` | SSE stream for real-time push |

---

## Default Credentials

| Username | Password | Role |
|----------|----------|------|
| admin | admin123 | admin |
| analyst | analyst123 | analyst |

**Change these before any production deployment.**
