# 🛡️ SOC Platform — College Lab Monitoring Project

A custom SOC platform in Python for lab/classroom monitoring.
Includes cross-platform agents, centralized rule engine, dashboard, and local AI-style teacher insights.

---

## 📁 Project Structure

```
soc-platform/
├── agent/
│   ├── agent.py            ← Main agent entrypoint
│   ├── student_monitor.py  ← Linux monitor
│   └── mac_monitor.py      ← macOS monitor
├── manager/
│   └── manager.py          ← Central server
├── rule_engine/
│   ├── engine.py           ← Alert matching + dedup logic
│   └── rules.json          ← Detection rules
├── dashboard/
│   ├── api.py              ← FastAPI + auth + report endpoints
│   ├── teacher_insights.py ← AI-style local teacher analytics
│   └── templates/index.html
├── database/db.py          ← SQLite storage + pruning
├── shared/
│   ├── config.py           ← Environment/config values
│   └── models.py           ← Shared models
└── requirements.txt
```

---

## ⚙️ Setup

```bash
# 1. Clone / copy the project
cd soc-platform

# 2. Install dependencies
pip install -r requirements.txt
```

Optional but recommended:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

---

## 🚀 Running the Platform

### Step 1 — Start Manager (server)
```bash
cd soc-platform
python -m manager.manager
```

### Step 2 — Start API + Dashboard (same server, new terminal)
```bash
API_HOST=127.0.0.1 API_PORT=8000 \
DASHBOARD_SESSION_SECRET=your-long-random-secret \
python -m dashboard.api

# Open: http://127.0.0.1:8000
# Login page: http://127.0.0.1:8000/login
```

### Step 3 — Start Agent (each monitored machine)
```bash
MANAGER_HOST=SERVER_IP MANAGER_PORT=9000 \
AGENT_ID=agent-002 AGENT_HOSTNAME=lab-pc-2 \
python -m agent.agent
```

---

## 📋 Key Configuration

| Variable | Description |
|---|---|
| `MANAGER_HOST` | Manager bind/connect host |
| `MANAGER_PORT` | Manager TCP port (default `9000`) |
| `API_HOST` | Dashboard API host (default `0.0.0.0`) |
| `API_PORT` | Dashboard API port (default `8000`) |
| `TEACHER_ACCOUNTS` | Teacher credentials as `user:pass,user2:pass2,...` |
| `DASHBOARD_SESSION_SECRET` | Session secret key |
| `AGENT_ID` | Unique machine/agent id |
| `AGENT_HOSTNAME` | Human-readable machine name |
| `AGENT_SEND_INTERVAL` | Agent send interval in seconds |

Default auto-created teacher accounts (when `TEACHER_ACCOUNTS` is not set):
`teacher01/Lab@Teacher01`, `teacher02/Lab@Teacher02`, `teacher03/Lab@Teacher03`,
`teacher04/Lab@Teacher04`, `teacher05/Lab@Teacher05`, `teacher06/Lab@Teacher06`,
`teacher07/Lab@Teacher07`, `teacher08/Lab@Teacher08`, `teacher09/Lab@Teacher09`.

---

## 📏 Adding Detection Rules

Edit `rule_engine/rules.json` and restart manager (recommended), or call reload API:

```bash
curl -X POST http://127.0.0.1:8000/api/rules/reload
```

Rule format:
```json
{
  "id": "R009",
  "name": "My Custom Rule",
  "description": "Detects something suspicious",
  "severity": "HIGH",
  "pattern": "regex pattern here",
  "source_filter": null
}
```

---

## 🌟 Main Features

- Cross-platform monitoring (Linux/macOS + Windows integrations)
- Rule-based alerting with dedup support
- Dashboard with acknowledgements and severity filters
- Per-teacher login accounts (`/login`)
- AI Chatbot panel for teacher questions (local analytics)
- One-click class period report card (print-friendly)
- Storage control via data pruning endpoint

---

## 🌐 API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/agents` | List all agents |
| GET | `/api/alerts` | List alerts (filter: ?severity=HIGH) |
| GET | `/api/alerts/stats` | Alert counts per severity |
| POST | `/api/alerts/{id}/acknowledge` | Acknowledge an alert |
| GET | `/api/logs` | Recent logs |
| GET | `/api/insights/teacher` | Teacher AI summary/analytics |
| GET | `/api/insights/teacher/stream` | Real-time teacher insights stream (SSE) |
| GET | `/api/insights/ask` | Ask teacher chatbot (summary/AI/gaming) |
| GET | `/api/reports/class-period` | One-click HTML report card |
| POST | `/api/maintenance/prune` | Prune old logs/alerts |
| POST | `/api/rules/reload` | Hot-reload rules.json |

Auth routes:

| Method | Endpoint | Description |
|---|---|---|
| GET | `/login` | Login page |
| POST | `/login` | Teacher username+password login |
| GET | `/logout` | End session |
| GET | `/api/auth/me` | Current logged-in teacher |
| GET | `/api/auth/access-log` | Recent teacher dashboard access sessions |

---

## 🗺️ Architecture

```
[Lab Machines]
    │
    │  TCP (port 9000)
    ▼
[Manager Server]  ←─ receives all log events
    │
    ├──► [Rule Engine]  ←─ matches patterns → generates alerts
    │
    └──► [SQLite DB]    ←─ stores logs + alerts
              │
              ▼
        [FastAPI Server]  ←─ REST API
              │
              ▼
        [Dashboard UI]    ←─ browser at :8000
```

---

## 🔮 Future Improvements

- [ ] Role-based access controls
- [ ] MFA / OTP login for dashboard
- [ ] Scheduled PDF export + email to faculty
- [ ] PostgreSQL for larger deployments
- [ ] Agent health watchdog + auto-recovery
- [ ] Advanced correlation across machines/time windows





//
