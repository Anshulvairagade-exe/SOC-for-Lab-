from shared.logger import get_logger
logger = get_logger("Database")
# ============================================================
#  SOC Platform - Database Layer
#  SQLite optimized for 60+ concurrent agents
#  Uses connection pooling and batch inserts
# ============================================================

import sqlite3
import os
import sys
import time
import threading

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
from shared.config import DB_PATH
from shared.models import LogEvent, Alert

# Connection pool for thread safety
_local = threading.local()


def get_connection():
    """
    Get a thread-local SQLite connection.
    - WAL mode: allows concurrent readers + 1 writer
    - Increased cache for better performance
    - Optimized for 60+ agents
    """
    if not hasattr(_local, 'conn') or _local.conn is None:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=30)
        conn.row_factory = sqlite3.Row
        # Performance optimizations
        conn.execute("PRAGMA journal_mode=WAL")        # Concurrent access
        conn.execute("PRAGMA synchronous=NORMAL")      # Faster writes
        conn.execute("PRAGMA cache_size=10000")        # 10MB cache
        conn.execute("PRAGMA temp_store=MEMORY")       # Temp tables in RAM
        conn.execute("PRAGMA mmap_size=268435456")     # 256MB memory-mapped I/O
        _local.conn = conn
    return _local.conn


# ─────────────────────────────────────────────
#  Schema Setup
# ─────────────────────────────────────────────
def init_db():
    """Create tables and indexes. Safe to call on every startup."""
    conn = get_connection()
    cur  = conn.cursor()

    # --- Agents table ---
    cur.execute("""
        CREATE TABLE IF NOT EXISTS agents (
            agent_id    TEXT PRIMARY KEY,
            hostname    TEXT NOT NULL,
            last_seen   REAL NOT NULL,
            status      TEXT DEFAULT 'active'
        )
    """)

    # --- Logs table ---
    cur.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id    TEXT NOT NULL,
            hostname    TEXT NOT NULL,
            source      TEXT NOT NULL,
            raw_log     TEXT NOT NULL,
            timestamp   REAL NOT NULL
        )
    """)

    # --- Alerts table ---
    cur.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            rule_id     TEXT NOT NULL,
            rule_name   TEXT NOT NULL,
            severity    TEXT NOT NULL,
            agent_id    TEXT NOT NULL,
            hostname    TEXT NOT NULL,
            matched_log TEXT NOT NULL,
            timestamp   REAL NOT NULL,
            acknowledged INTEGER DEFAULT 0
        )
    """)

    # --- Indexes for faster queries (critical for 60+ agents) ---
    cur.execute("CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs(timestamp DESC)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_logs_agent ON logs(agent_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp DESC)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_alerts_ack ON alerts(acknowledged)")

    conn.commit()
    conn.close(); _local.conn = None
    logger.info(f"Database initialized at {DB_PATH}")


# ─────────────────────────────────────────────
#  Agent Operations
# ─────────────────────────────────────────────
def upsert_agent(agent_id: str, hostname: str):
    """Register a new agent or update its last_seen timestamp."""
    conn = get_connection()
    conn.execute("""
        INSERT INTO agents (agent_id, hostname, last_seen)
        VALUES (?, ?, ?)
        ON CONFLICT(agent_id) DO UPDATE SET
            hostname  = excluded.hostname,
            last_seen = excluded.last_seen,
            status    = 'active'
    """, (agent_id, hostname, time.time()))
    conn.commit()
    conn.close(); _local.conn = None


def get_all_agents() -> list[dict]:
    conn = get_connection()
    rows = conn.execute("SELECT * FROM agents ORDER BY last_seen DESC").fetchall()
    conn.close(); _local.conn = None
    return [dict(r) for r in rows]


# ─────────────────────────────────────────────
#  Log Operations
# ─────────────────────────────────────────────
def insert_log(event: LogEvent):
    """Save a LogEvent to the database."""
    conn = get_connection()
    conn.execute("""
        INSERT INTO logs (agent_id, hostname, source, raw_log, timestamp)
        VALUES (?, ?, ?, ?, ?)
    """, (event.agent_id, event.hostname, event.source, event.raw_log, event.timestamp))
    conn.commit()
    conn.close(); _local.conn = None


def get_logs(limit: int = 100, agent_id: str = None) -> list[dict]:
    """Fetch recent logs, optionally filtered by agent."""
    conn = get_connection()
    if agent_id:
        rows = conn.execute(
            "SELECT * FROM logs WHERE agent_id=? ORDER BY timestamp DESC LIMIT ?",
            (agent_id, limit)
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM logs ORDER BY timestamp DESC LIMIT ?", (limit,)
        ).fetchall()
    conn.close(); _local.conn = None
    return [dict(r) for r in rows]


# ─────────────────────────────────────────────
#  Alert Operations
# ─────────────────────────────────────────────
def insert_alert(alert: Alert):
    """Save an Alert to the database."""
    conn = get_connection()
    conn.execute("""
        INSERT INTO alerts
            (rule_id, rule_name, severity, agent_id, hostname, matched_log, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        alert.rule_id, alert.rule_name, alert.severity,
        alert.agent_id, alert.hostname, alert.matched_log, alert.timestamp
    ))
    conn.commit()
    conn.close(); _local.conn = None


def get_alerts(limit: int = 100, severity: str = None, date_str: str = None) -> list[dict]:
    """Fetch recent alerts, optionally filtered by severity and date (YYYY-MM-DD)."""
    conn = get_connection()
    
    query = "SELECT * FROM alerts WHERE 1=1"
    params = []
    
    if severity:
        query += " AND severity=?"
        params.append(severity)
        
    if date_str:
        import datetime
        try:
            dt = datetime.datetime.strptime(date_str, '%Y-%m-%d')
            start_ts = dt.timestamp()
            end_ts = start_ts + 86400
            query += " AND timestamp >= ? AND timestamp < ?"
            params.extend([start_ts, end_ts])
        except ValueError:
            pass
            
    query += " ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)
    
    rows = conn.execute(query, tuple(params)).fetchall()
    conn.close(); _local.conn = None
    return [dict(r) for r in rows]


def acknowledge_alert(alert_id: int):
    """Mark an alert as acknowledged (reviewed by analyst)."""
    conn = get_connection()
    conn.execute("UPDATE alerts SET acknowledged=1 WHERE id=?", (alert_id,))
    conn.commit()
    conn.close(); _local.conn = None


def get_alert_counts() -> dict:
    """Get alert counts grouped by severity (for dashboard stats)."""
    conn = get_connection()
    rows = conn.execute("""
        SELECT severity, COUNT(*) as count
        FROM alerts
        WHERE acknowledged = 0
        GROUP BY severity
    """).fetchall()
    conn.close(); _local.conn = None
    return {r["severity"]: r["count"] for r in rows}


def prune_old_data(log_days: int = 7, alert_days: int = 30) -> dict:
    """
    Delete old rows to reduce storage use.
    Returns number of deleted rows from each table.
    """
    import time

    now = time.time()
    log_cutoff = now - (max(1, int(log_days)) * 86400)
    alert_cutoff = now - (max(1, int(alert_days)) * 86400)

    conn = get_connection()
    cur = conn.cursor()

    cur.execute("DELETE FROM logs WHERE timestamp < ?", (log_cutoff,))
    deleted_logs = cur.rowcount if cur.rowcount is not None else 0

    cur.execute("DELETE FROM alerts WHERE timestamp < ?", (alert_cutoff,))
    deleted_alerts = cur.rowcount if cur.rowcount is not None else 0

    conn.commit()
    conn.close(); _local.conn = None

    return {
        "logs": deleted_logs,
        "alerts": deleted_alerts,
    }
