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
DASHBOARD_SESSION_SECRET = os.getenv("DASHBOARD_SESSION_SECRET", "soc-dashboard-dev-secret-change")
DASHBOARD_LOGIN_RATE_LIMIT_ATTEMPTS = int(os.getenv("DASHBOARD_LOGIN_RATE_LIMIT_ATTEMPTS", "5"))
DASHBOARD_LOGIN_RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("DASHBOARD_LOGIN_RATE_LIMIT_WINDOW_SECONDS", "120"))
DASHBOARD_LOGIN_RATE_LIMIT_LOCKOUT_SECONDS = int(os.getenv("DASHBOARD_LOGIN_RATE_LIMIT_LOCKOUT_SECONDS", "120"))


def _default_teacher_accounts() -> list[tuple[str, str]]:
    return [
        ("teacher01", "Lab@Teacher01"),
        ("teacher02", "Lab@Teacher02"),
        ("teacher03", "Lab@Teacher03"),
        ("teacher04", "Lab@Teacher04"),
        ("teacher05", "Lab@Teacher05"),
        ("teacher06", "Lab@Teacher06"),
        ("teacher07", "Lab@Teacher07"),
        ("teacher08", "Lab@Teacher08"),
        ("teacher09", "Lab@Teacher09"),
    ]


def _parse_teacher_accounts(raw_value: str | None) -> list[tuple[str, str]]:
    if not raw_value:
        return _default_teacher_accounts()

    parsed_accounts: list[tuple[str, str]] = []
    for entry in raw_value.split(","):
        item = entry.strip()
        if not item:
            continue
        if ":" not in item:
            continue
        username, password = item.split(":", 1)
        username = username.strip()
        password = password.strip()
        if username and password:
            parsed_accounts.append((username, password))

    if not parsed_accounts:
        return _default_teacher_accounts()

    return parsed_accounts


TEACHER_ACCOUNTS = _parse_teacher_accounts(os.getenv("TEACHER_ACCOUNTS"))

# --- Database ---
DB_PATH = os.getenv("DB_PATH", str(BASE_DIR / "soc_platform.db"))        # SQLite file path

# --- Agent ---
AGENT_SEND_INTERVAL = int(os.getenv("AGENT_SEND_INTERVAL", "1"))            # Seconds between log checks
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
