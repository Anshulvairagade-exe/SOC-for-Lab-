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


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


MANAGER_HOST = os.getenv("MANAGER_HOST", "139.59.50.143")           # Listen on all interfaces
MANAGER_PORT = int(os.getenv("MANAGER_PORT", "9000"))         # Port agents connect to
MANAGER_BUFFER_SIZE = 8192         # Increased buffer for bulk events
MANAGER_MAX_CONNECTIONS = 100      # Max concurrent agent connections

# --- API Server ---
API_HOST = os.getenv("API_HOST", "139.59.50.143")
API_PORT = int(os.getenv("API_PORT", "8000"))
DASHBOARD_AUTO_RELOAD = _env_bool("DASHBOARD_AUTO_RELOAD", True)

# --- Dashboard Access Control ---
DASHBOARD_SESSION_SECRET = os.getenv("DASHBOARD_SESSION_SECRET", "soc-dashboard-dev-secret-change")
DASHBOARD_LOGIN_RATE_LIMIT_ATTEMPTS = int(os.getenv("DASHBOARD_LOGIN_RATE_LIMIT_ATTEMPTS", "5"))
DASHBOARD_LOGIN_RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("DASHBOARD_LOGIN_RATE_LIMIT_WINDOW_SECONDS", "120"))
DASHBOARD_LOGIN_RATE_LIMIT_LOCKOUT_SECONDS = int(os.getenv("DASHBOARD_LOGIN_RATE_LIMIT_LOCKOUT_SECONDS", "120"))

RBAC_ROLES = {"teacher", "admin"}


def _default_allowed_hostnames(username: str) -> list[str]:
    digits = "".join(ch for ch in username if ch.isdigit())
    if not digits:
        return []
    return [f"lab-machine-{int(digits)}"]


def _normalize_role(role: str | None) -> str:
    role_value = (role or "teacher").strip().lower()
    return role_value if role_value in RBAC_ROLES else "teacher"


def _default_teacher_accounts() -> list[dict]:
    return [
        {
            "username": f"teacher{idx:02d}",
            "password": f"Lab@Teacher{idx:02d}",
            "role": "teacher",
            "allowed_hostnames": [f"lab-machine-{idx}"],
        }
        for idx in range(1, 10)
    ]


def _parse_allowed_hostnames(raw_value: str | None) -> list[str]:
    if not raw_value:
        return []

    items = [
        part.strip()
        for chunk in raw_value.replace(";", "|").split("|")
        for part in [chunk]
        if part.strip()
    ]
    normalized = sorted({item for item in items if item})
    if "*" in normalized or "all" in {item.lower() for item in normalized}:
        return ["*"]
    return normalized


def _parse_teacher_accounts(raw_value: str | None) -> list[dict]:
    if not raw_value:
        return _default_teacher_accounts()

    parsed_accounts: list[dict] = []
    for entry in raw_value.split(","):
        item = entry.strip()
        if not item:
            continue
        if ":" not in item:
            continue

        parts = item.split(":", 3)
        if len(parts) < 2:
            continue

        username, password = parts[0], parts[1]
        username = username.strip()
        password = password.strip()
        role = _normalize_role(parts[2] if len(parts) >= 3 else "teacher")
        allowed_hostnames = _parse_allowed_hostnames(parts[3] if len(parts) >= 4 else "")

        if role == "admin":
            allowed_hostnames = ["*"]
        elif not allowed_hostnames:
            allowed_hostnames = _default_allowed_hostnames(username)

        if username and password:
            parsed_accounts.append(
                {
                    "username": username,
                    "password": password,
                    "role": role,
                    "allowed_hostnames": allowed_hostnames,
                }
            )

    if not parsed_accounts:
        return _default_teacher_accounts()

    return parsed_accounts

# TEACHER_ACCOUNTS format:
#   username:password
#   username:password:teacher:lab-machine-2|lab-machine-3
#   admin:strongpass:admin:*
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
