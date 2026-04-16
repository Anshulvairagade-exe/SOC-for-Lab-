# ============================================================
#  SOC Platform - Shared Configuration
#  PRODUCTION CONFIG — optimized for 60+ concurrent agents
# ============================================================

# === Manager Server ===
import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()
BASE_DIR = Path(__file__).resolve().parent.parent

MANAGER_HOST = os.getenv("MANAGER_HOST", "0.0.0.0")           # Listen on all interfaces
MANAGER_PORT = int(os.getenv("MANAGER_PORT", "9000"))         # Port agents connect to
MANAGER_BUFFER_SIZE = 8192         # Increased buffer for bulk events
MANAGER_MAX_CONNECTIONS = 100      # Max concurrent agent connections

# --- API Server ---
API_HOST = os.getenv("API_HOST", "0.0.0.0")
API_PORT = int(os.getenv("API_PORT", "8000"))

# --- Dashboard Access Control ---
DASHBOARD_PASSWORD = os.getenv("DASHBOARD_PASSWORD", "9022425319")
DASHBOARD_SESSION_SECRET = os.getenv("DASHBOARD_SESSION_SECRET", "soc-dashboard-dev-secret-change")

# --- Database ---
DB_PATH = os.getenv("DB_PATH", str(BASE_DIR / "soc_platform.db"))        # SQLite file path

# --- Agent ---
AGENT_SEND_INTERVAL = int(os.getenv("AGENT_SEND_INTERVAL", "2"))            # Seconds between log batches
AGENT_ID = os.getenv("AGENT_ID", "agent-001")             # Unique ID per machine (change per install)
AGENT_HOSTNAME = os.getenv("AGENT_HOSTNAME", "lab-machine-1")   # Human-readable name
AGENT_RECONNECT_DELAY = 5          # Seconds to wait before reconnecting
AGENT_HEARTBEAT_INTERVAL = 10      # Seconds between heartbeats

# --- Severity Levels ---
SEVERITY = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4
}

# --- Log Sources (Agent collects these) ---
LOG_SOURCES = [
    "/var/log/syslog",
    "/var/log/auth.log",
]

# --- File Integrity Monitoring ---
FIM_WATCH_PATHS = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/hosts",
]
