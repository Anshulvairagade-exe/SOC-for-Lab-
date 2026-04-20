# Windows Setup Guide — SOC Platform

**Version:** Production | **Platform:** Windows 10/11 + Windows Server 2019/2022

---

## 📐 Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│  MANAGER SERVER  (Teacher/Admin Machine)                    │
│  ─────────────────────────────────────────────────          │
│  manager/manager.py  → TLS TCP Server     Port: 9000        │
│  dashboard/api.py    → FastAPI REST API   Port: 8000        │
│  database/db.py      → SQLite (WAL mode)  soc_platform.db   │
│  rule_engine/        → Real-time Alert SIEM                 │
│  manager/certs/      → Auto-generated TLS Certificates      │
└─────────────────────────────────────────────────────────────┘
              ▲  TLS v1.2 Encrypted TCP (Port 9000)
              │
    ┌─────────┴────────┬────────────┬────────────┐
    │                  │            │            │
┌───┴───┐         ┌────┴────┐  ┌───┴────┐  ┌───┴────┐
│ PC-01 │         │  PC-02  │  │ PC-03  │  │  ...   │
│ agent │         │  agent  │  │  agent │  │        │
│ .py   │         │  .py    │  │  .py   │  │        │
└───────┘         └─────────┘  └────────┘  └────────┘
     Student Lab Machines (Monitoring Agents)
```

### What Each Component Does

| File | Role |
|---|---|
| `manager/manager.py` | TCP server — receives all agent telemetry over TLS, evaluates rules |
| `dashboard/api.py` | FastAPI REST service — serves the React dashboard and query endpoints |
| `agent/agent.py` | Endpoint agent — collects system, browser, process, and USB events |
| `agent/student_monitor.py` | Windows-specific: active window, USB, shell, screenshot, login tracking |
| `agent/browser_monitor.py` | Chrome/Edge/Brave/Firefox history collector via SQLite |
| `agent/windows_eventlog.py` | Windows Security/System/Application Event Log reader |
| `agent/windows_monitors.py` | Process, PowerShell, USB, and Active Window monitors |
| `rule_engine/rules.json` | All 39+ alert detection rules (editable without restart) |
| `database/db.py` | SQLite WAL-mode database layer |
| `shared/security.py` | TLS Certificate generation + JWT auth |
| `shared/logger.py` | Unified structured logging across all components |
| `shared/config.py` | Central config pulled from `.env` |

---

## 🛠️ Prerequisites

### Required Software

| Software | Version | Notes |
|---|---|---|
| Python | 3.10+ | Required |
| pip | Latest | Comes with Python |
| SQLite | Built-in | Bundled with Python |

### Python Dependencies
Install all dependencies in one command:
```powershell
pip install -r requirements.txt
```

**`requirements.txt` installs:**
- `fastapi`, `uvicorn` — Dashboard API server
- `psutil` — System process/resource monitoring
- `pywin32`, `wmi` — Windows Event Log, USB, process monitoring
- `python-dotenv` — .env configuration loading
- `cryptography`, `PyJWT` — TLS certificate generation and JWT tokens
- `requests` — Internal HTTP calls

---

## ⚙️ Configuration (.env File)

Copy the example file and edit it:
```powershell
copy .env.example .env
notepad .env
```

### Key Variables

```ini
# ─── Manager Network ───────────────────────────────────────────
MANAGER_HOST=0.0.0.0          # Manager bind address (0.0.0.0 = all interfaces)
MANAGER_PORT=9000             # Port agents connect to

# ─── Agent Identity (set unique per machine) ────────────────────
AGENT_ID=agent-pc-01          # Unique agent identifier
AGENT_HOSTNAME=lab-pc-01      # Friendly display name in dashboard
MANAGER_HOST=192.168.1.100    # (on agent .env) IP of Manager machine
AGENT_SEND_INTERVAL=1         # How often agent checks/sends logs (seconds)

# ─── Dashboard API ──────────────────────────────────────────────
DASHBOARD_HOST=0.0.0.0
DASHBOARD_PORT=8000

# ─── Security ───────────────────────────────────────────────────
AUTH_SECRET_KEY=change-this-to-a-long-random-string
API_KEY=your-dashboard-password

# ─── Privacy: Monitored feature flags ───────────────────────────
MONITOR_BROWSER_HISTORY=true
MONITOR_ACTIVE_WINDOW=true
MONITOR_USB_DEVICES=true
MONITOR_SHELL_COMMANDS=true
MONITOR_PROCESSES=true

# ─── Privacy: Restrict URLs collected to specific domains ───────
# Leave blank to collect ALL URLs
BROWSER_ALLOWED_DOMAINS=

# ─── Retention ──────────────────────────────────────────────────
LOG_RETENTION_DAYS=30
ALERT_RETENTION_DAYS=90
```

---

## 🚀 Running the Platform

### Order of Operations (start in this exact order)

**Step 1 — Start the Manager Server**
```powershell
# From d:\Project\SOC\soc-platform\
python manager/manager.py
```
✅ Expected output:
```
2026-04-09 14:55:28 | INFO | [RuleEngine] Loaded 39 rules ...
2026-04-09 14:55:28 | INFO | [Manager] Generating Self-Signed Certificates for TLS...
2026-04-09 14:55:28 | INFO | [Manager] Initializing TLS SecureSocket Listener...
2026-04-09 14:55:28 | INFO | [Manager] Waiting for agents...
```

> [!NOTE]
> TLS certificates are **automatically generated** on first run into `manager/certs/` folder. No manual certificate steps are needed.

---

**Step 2 — Start the Dashboard API**
```powershell
python dashboard/api.py
```
✅ Expected output:
```
INFO:     Uvicorn running on http://0.0.0.0:8000
```
Then open your browser at: **http://localhost:8000**

---

**Step 3 — Start the Agent**

> [!IMPORTANT]
> For **Full System Monitoring** (Security Event Logs, deep process tracking), run as **Administrator**:
> Right-click your terminal → **Run as Administrator** → then run the agent.

```powershell
python agent/agent.py
```
✅ Expected output:
```
2026-04-09 15:10:26 | INFO | [Agent] Starting | ID=agent-001 | Host=lab-machine-1
2026-04-09 15:10:26 | INFO | [Agent] Connected.
2026-04-09 15:10:31 | INFO | [Agent] Sent 3 logs
```

> [!WARNING]
> If you see `[WindowsEventLog] Failed to initialize Security: ... 'A required privilege is not held by the client.'`  
> This means the agent is running **without Administrator** privileges. Security Event Logs will be skipped, but all other monitoring (browser, USB, processes, windows) will still work normally.

---

## 🔒 Windows Firewall Configuration

Run once on the **Manager machine** as Administrator:

```powershell
# Allow agents to connect on port 9000 (TLS)
New-NetFirewallRule -DisplayName "SOC Manager - Agent Port" `
    -Direction Inbound -Protocol TCP -LocalPort 9000 -Action Allow

# Allow dashboard browser access on port 8000
New-NetFirewallRule -DisplayName "SOC Dashboard" `
    -Direction Inbound -Protocol TCP -LocalPort 8000 -Action Allow
```

Run once on each **Agent machine**:
```powershell
# Allow outbound connection to Manager
New-NetFirewallRule -DisplayName "SOC Agent Outbound" `
    -Direction Outbound -Protocol TCP -RemotePort 9000 -Action Allow
```

---

## 🏫 Lab-Wide Deployment

### Manager Server Requirements
| Resource | Minimum | Recommended |
|---|---|---|
| CPU | 2 cores | 4 cores |
| RAM | 4 GB | 8 GB |
| Disk | 20 GB | 100 GB |
| OS | Windows 10 | Windows Server 2019+ |

### Agent Machine Requirements
| Resource | Minimum |
|---|---|
| CPU | Any |
| RAM | 256 MB free |
| Python | 3.10+ |
| OS | Windows 10/11 |

### Mass Deployment Script (Run on each lab PC)
```powershell
# Set your manager server IP here
$managerIP = "192.168.1.100"
$pcName = $env:COMPUTERNAME
$agentID = "agent-$pcName"

# Copy platform files from network share
Copy-Item "\\$managerIP\SOC\soc-platform" -Destination "C:\SOC\soc-platform" -Recurse -Force

# Write the .env file for this specific PC
@"
MANAGER_HOST=$managerIP
MANAGER_PORT=9000
AGENT_ID=$agentID
AGENT_HOSTNAME=$pcName
AGENT_SEND_INTERVAL=1
"@ | Out-File -FilePath "C:\SOC\soc-platform\.env" -Encoding ascii

# Install dependencies
cd C:\SOC\soc-platform
pip install -r requirements.txt

Write-Host "Deployment complete for $pcName (Agent ID: $agentID)"
```

### Group Policy (GPO) Auto-Start

To auto-start the agent on login:
1. Open `gpedit.msc`
2. Navigate to: `Computer Configuration → Windows Settings → Scripts → Startup`
3. Add: `python C:\SOC\soc-platform\agent\agent.py`

---

## 🌐 Security & TLS

### How Encryption Works
The platform uses **self-signed TLS v1.2** certificates:
- Manager auto-generates `server.crt` and `server.key` in `manager/certs/` on first boot
- All agent-to-manager TCP traffic is encrypted — cannot be intercepted on the lab network
- The dashboard API (port 8000) is plain HTTP — restrict access to the teacher network/VLAN

### Certificate Renewal
Certificates expire after **365 days**. To regenerate:
```powershell
# Delete old certs and restart manager (auto-generates new ones)
Remove-Item -Recurse -Force manager\certs\
python manager/manager.py
```

---

## 🔧 Troubleshooting

### Port Already in Use (Error 10048)
```powershell
# Find and kill the process occupying port 8000 or 9000
$pid8000 = (Get-NetTCPConnection -LocalPort 8000 -EA SilentlyContinue).OwningProcess
if ($pid8000) { Stop-Process -Id $pid8000 -Force; echo "Freed port 8000" }

$pid9000 = (Get-NetTCPConnection -LocalPort 9000 -EA SilentlyContinue).OwningProcess
if ($pid9000) { Stop-Process -Id $pid9000 -Force; echo "Freed port 9000" }
```

### Kill All Python Processes (Emergency Reset)
```powershell
Stop-Process -Name "python" -Force
```

### Agent Shows "Sent 0 logs" Constantly
- This is **normal** when the system is idle — the agent only reports new events
- To verify it's working: open a browser, visit a website, wait 5-10 seconds, check the dashboard

### "ModuleNotFoundError: No module named 'shared'"
Run commands from the **project root** (`soc-platform/`), not from inside a subfolder:
```powershell
# CORRECT
cd d:\Project\SOC\soc-platform
python manager/manager.py

# WRONG
cd d:\Project\SOC\soc-platform\manager
python manager.py
```

### Agent cannot connect to Manager
```powershell
# 1. Verify manager is listening
netstat -an | findstr 9000

# 2. Test connectivity from agent machine
Test-NetConnection -ComputerName 192.168.1.100 -Port 9000

# 3. Verify .env has correct MANAGER_HOST
type .env | findstr MANAGER_HOST
```

### Security Event Logs Not Collected
```powershell
# Add current user to Event Log Readers group (requires admin)
net localgroup "Event Log Readers" %USERNAME% /add
# Then log out and back in, restart agent
```

### Browser History Not Collected
1. Close the target browser completely (SQLite DB is locked while browser is open)
2. Wait for the next agent poll cycle (default 5 seconds)
3. Verify `MONITOR_BROWSER_HISTORY=true` in `.env`

### Dashboard Shows No Data
```powershell
# Confirm API is running
Invoke-RestMethod http://localhost:8000/api/agents

# Check alert stats
Invoke-RestMethod http://localhost:8000/api/alerts/stats
```

---

## 📋 Pre-Deployment Checklist

### Manager Machine
- [ ] Python 3.10+ installed
- [ ] `pip install -r requirements.txt` completed successfully
- [ ] `.env` file created and configured with secure `AUTH_SECRET_KEY`
- [ ] Firewall rules added for ports 9000 and 8000
- [ ] Static IP assigned to manager machine
- [ ] `python manager/manager.py` starts and shows "Waiting for agents..."
- [ ] `python dashboard/api.py` reachable at `http://localhost:8000`
- [ ] TLS certs auto-generated in `manager/certs/`

### Each Agent Machine
- [ ] Python 3.10+ installed
- [ ] `pip install -r requirements.txt` completed successfully
- [ ] `.env` file has unique `AGENT_ID` and correct `MANAGER_HOST` IP
- [ ] Firewall outbound rule added for port 9000
- [ ] Agent connects and shows "Connected." in terminal
- [ ] Dashboard shows agent in the Agents panel
- [ ] Alerts are generated on suspicious activity

### Legal & Policy
- [ ] Student monitoring policy disclosed (see student notice template below)
- [ ] Data retention policy configured in `.env`
- [ ] Only authorized staff have dashboard access

---

## 📋 Student Lab Monitoring Notice Template

Display this at lab entry and on login screens:

```
╔════════════════════════════════════════════════╗
║         COMPUTER LAB MONITORING NOTICE         ║
╠════════════════════════════════════════════════╣
║                                                ║
║  This lab is monitored for academic integrity  ║
║  and security purposes.                        ║
║                                                ║
║  Monitored activities include:                 ║
║  • Application and window usage                ║
║  • Web browser history                         ║
║  • USB device connections                      ║
║  • System events                               ║
║                                                ║
║  Data is retained for 30 days.                 ║
║  Access restricted to authorized staff only.  ║
║                                                ║
║  By using this lab, you agree to monitoring.  ║
║                                                ║
║  Questions: admin@youruniversity.edu           ║
╚════════════════════════════════════════════════╝
```

---

## 📁 Project File Reference

```
soc-platform/
├── agent/
│   ├── agent.py              ← Main agent entry point
│   ├── browser_monitor.py    ← Chrome/Firefox/Brave history
│   ├── student_monitor.py    ← Windows-specific full monitoring
│   ├── windows_eventlog.py   ← Security/System/App Event Logs
│   └── windows_monitors.py   ← USB, PowerShell, Process, Window
├── dashboard/
│   ├── api.py                ← FastAPI REST endpoints
│   └── templates/
│       └── index.html        ← React-powered dashboard UI
├── database/
│   └── db.py                 ← SQLite WAL database layer
├── manager/
│   ├── manager.py            ← TLS TCP server + rule evaluator
│   └── certs/                ← Auto-generated TLS certificates
├── rule_engine/
│   ├── engine.py             ← SIEM rule evaluation engine
│   └── rules.json            ← 39+ detection rules (editable)
├── shared/
│   ├── config.py             ← .env configuration loader
│   ├── logger.py             ← Unified structured logger
│   ├── models.py             ← LogEvent, Alert data models
│   ├── os_abstraction.py     ← Cross-platform OS helper
│   └── security.py           ← TLS + JWT auth module
├── .env                      ← Your local configuration (not committed)
├── .env.example              ← Template for .env
├── requirements.txt          ← Python dependencies
└── soc_platform.db           ← SQLite database (auto-created)
```
