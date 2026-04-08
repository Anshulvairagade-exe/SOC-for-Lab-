# ============================================================
#  SOC Platform - Shared Configuration
#  PRODUCTION CONFIG — optimized for 60+ concurrent agents
# ============================================================

# --- Manager Server ---
MANAGER_HOST = "0.0.0.0"           # Listen on all interfaces
MANAGER_PORT = 9000                # Port agents connect to
MANAGER_BUFFER_SIZE = 8192         # Increased buffer for bulk events
MANAGER_MAX_CONNECTIONS = 100      # Max concurrent agent connections

# --- API Server ---
API_HOST = "0.0.0.0"
API_PORT = 8000

# --- Database ---
DB_PATH = "soc_platform.db"        # SQLite file path

# --- Agent ---
AGENT_SEND_INTERVAL = 2            # Seconds between log batches (reduced server load)
AGENT_ID = "agent-001"             # Unique ID per machine (change per install)
AGENT_HOSTNAME = "lab-machine-1"   # Human-readable name
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
