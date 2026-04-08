# 🛡️ SOC Platform — College Lab Project

A custom-built Security Operations Center (SOC) platform in Python.
Built as an alternative to Wazuh for your college lab setup.

---

## 📁 Project Structure

```
soc-platform/
├── agent/
│   └── agent.py            ← Run on each monitored machine
├── manager/
│   └── manager.py          ← Central server (run once)
├── rule_engine/
│   ├── engine.py           ← Alert matching logic
│   └── rules.json          ← Define your detection rules here
├── dashboard/
│   ├── api.py              ← FastAPI REST API + serves dashboard
│   └── templates/
│       └── index.html      ← Web dashboard UI
├── database/
│   └── db.py               ← SQLite storage layer
├── shared/
│   ├── config.py           ← All settings in one place
│   └── models.py           ← Shared data classes
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

---

## 🚀 Running the Platform

### Step 1 — Start the Central Manager  (on the server machine)
```bash
cd soc-platform
python manager/manager.py
```

### Step 2 — Start the API + Dashboard  (same server, different terminal)
```bash
python dashboard/api.py
# Open browser → http://localhost:8000
```

### Step 3 — Start the Agent  (on each lab machine)
```bash
# Edit shared/config.py first:
#   MANAGER_HOST = "IP of your manager machine"
#   AGENT_ID     = unique ID per machine e.g. "agent-002"
#   AGENT_HOSTNAME = machine name e.g. "lab-pc-2"

python agent/agent.py
```

---

## 📋 Configuration (shared/config.py)

| Setting | Description |
|---|---|
| `MANAGER_HOST` | IP address of the manager server |
| `MANAGER_PORT` | TCP port agents connect to (default 9000) |
| `AGENT_ID` | Unique ID for each agent machine |
| `LOG_SOURCES` | List of log file paths to monitor |
| `FIM_WATCH_PATHS` | Files to watch for modifications |
| `AGENT_SEND_INTERVAL` | How often agent sends logs (seconds) |

---

## 📏 Adding Detection Rules

Edit `rule_engine/rules.json` — no restart needed, use the API:

```bash
curl -X POST http://localhost:8000/api/rules/reload
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

## 🌐 API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/agents` | List all agents |
| GET | `/api/alerts` | List alerts (filter: ?severity=HIGH) |
| GET | `/api/alerts/stats` | Alert counts per severity |
| POST | `/api/alerts/{id}/acknowledge` | Acknowledge an alert |
| GET | `/api/logs` | Recent logs |
| POST | `/api/rules/reload` | Hot-reload rules.json |

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

- [ ] TLS/SSL encryption on Agent ↔ Manager connection
- [ ] Agent authentication (token-based)
- [ ] Email / webhook notifications on CRITICAL alerts
- [ ] PostgreSQL for larger deployments
- [ ] Threat intelligence feed integration
- [ ] Log search with filters in dashboard
- [ ] Correlation rules (detect patterns across multiple events)
