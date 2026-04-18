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
from shared.config import TEACHER_ACCOUNTS
from shared.models import LogEvent, Alert
from shared.security import hash_password, verify_password

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

    # --- Dashboard teacher users ---
    cur.execute("""
        CREATE TABLE IF NOT EXISTS teacher_users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            created_at REAL NOT NULL
        )
    """)

    # --- Dashboard login sessions ---
    cur.execute("""
        CREATE TABLE IF NOT EXISTS teacher_login_sessions (
            session_id TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            login_at REAL NOT NULL,
            logout_at REAL,
            FOREIGN KEY (username) REFERENCES teacher_users(username)
        )
    """)

    # --- Dashboard login attempt tracking ---
    cur.execute("""
        CREATE TABLE IF NOT EXISTS teacher_login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            remote_addr TEXT NOT NULL,
            attempted_at REAL NOT NULL,
            success INTEGER NOT NULL DEFAULT 0
        )
    """)

    attempt_columns = {
        row["name"]
        for row in cur.execute("PRAGMA table_info(teacher_login_attempts)").fetchall()
    }
    if attempt_columns and {"remote_addr", "success"} - attempt_columns:
        legacy_remote_expr = "'unknown'"
        if "ip_address" in attempt_columns and "device_key" in attempt_columns:
            legacy_remote_expr = "COALESCE(ip_address, device_key, 'unknown')"
        elif "ip_address" in attempt_columns:
            legacy_remote_expr = "COALESCE(ip_address, 'unknown')"
        elif "device_key" in attempt_columns:
            legacy_remote_expr = "COALESCE(device_key, 'unknown')"

        legacy_username_expr = "COALESCE(username, '')" if "username" in attempt_columns else "''"
        legacy_attempted_at_expr = "attempted_at" if "attempted_at" in attempt_columns else str(time.time())
        legacy_success_expr = "COALESCE(successful, 0)" if "successful" in attempt_columns else "0"

        cur.execute("ALTER TABLE teacher_login_attempts RENAME TO teacher_login_attempts_legacy")
        cur.execute("""
            CREATE TABLE teacher_login_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                remote_addr TEXT NOT NULL,
                attempted_at REAL NOT NULL,
                success INTEGER NOT NULL DEFAULT 0
            )
        """)
        cur.execute(
            f"""
            INSERT INTO teacher_login_attempts (username, remote_addr, attempted_at, success)
            SELECT {legacy_username_expr}, {legacy_remote_expr}, {legacy_attempted_at_expr}, {legacy_success_expr}
            FROM teacher_login_attempts_legacy
            """
        )
        cur.execute("DROP TABLE teacher_login_attempts_legacy")

    # --- Indexes for faster queries (critical for 60+ agents) ---
    cur.execute("CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs(timestamp DESC)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_logs_agent ON logs(agent_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp DESC)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_alerts_ack ON alerts(acknowledged)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_teacher_login_username ON teacher_login_sessions(username)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_teacher_login_login_at ON teacher_login_sessions(login_at DESC)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_teacher_attempt_username ON teacher_login_attempts(username)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_teacher_attempt_remote_addr ON teacher_login_attempts(remote_addr)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_teacher_attempt_attempted_at ON teacher_login_attempts(attempted_at DESC)")

    # Seed teacher accounts and keep configured credentials in sync with SQLite.
    now = time.time()
    existing_teacher_rows = cur.execute(
        "SELECT username, password_hash FROM teacher_users"
    ).fetchall()
    existing_teacher_hashes = {
        row["username"]: row["password_hash"]
        for row in existing_teacher_rows
    }

    inserted_accounts = 0
    updated_accounts = 0
    for username, password in TEACHER_ACCOUNTS:
        stored_hash = existing_teacher_hashes.get(username)
        if stored_hash is None:
            cur.execute(
                "INSERT INTO teacher_users (username, password_hash, created_at) VALUES (?, ?, ?)",
                (username, hash_password(password), now),
            )
            inserted_accounts += 1
            continue

        if not verify_password(password, stored_hash):
            cur.execute(
                "UPDATE teacher_users SET password_hash = ? WHERE username = ?",
                (hash_password(password), username),
            )
            updated_accounts += 1

    cur.execute(
        "DELETE FROM teacher_login_attempts WHERE attempted_at < ?",
        (now - 86400,),
    )

    conn.commit()
    conn.close(); _local.conn = None
    if inserted_accounts or updated_accounts:
        logger.info(
            "Teacher credentials synchronized (inserted=%s, updated=%s)",
            inserted_accounts,
            updated_accounts,
        )
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


def authenticate_teacher(username: str, password: str) -> str | None:
    """Validate a dashboard teacher username/password pair and return the canonical username."""
    conn = get_connection()
    row = conn.execute(
        "SELECT username, password_hash FROM teacher_users WHERE lower(username) = lower(?)",
        (username.strip(),),
    ).fetchone()
    conn.close(); _local.conn = None
    if not row:
        return None
    if verify_password(password, row["password_hash"]):
        return row["username"]
    return None


def record_teacher_login_attempt(username: str, remote_addr: str, success: bool):
    """Record a login attempt for auditing and rate limiting."""
    normalized_username = username.strip()
    normalized_remote_addr = (remote_addr or "unknown").strip() or "unknown"
    attempt_time = time.time()

    conn = get_connection()
    conn.execute(
        """
        INSERT INTO teacher_login_attempts (username, remote_addr, attempted_at, success)
        VALUES (?, ?, ?, ?)
        """,
        (normalized_username, normalized_remote_addr, attempt_time, int(success)),
    )
    if success:
        conn.execute(
            """
            DELETE FROM teacher_login_attempts
            WHERE success = 0 AND username = ? AND remote_addr = ?
            """,
            (normalized_username, normalized_remote_addr),
        )
    conn.commit()
    conn.close(); _local.conn = None


def get_teacher_login_rate_limit_status(
    username: str,
    remote_addr: str,
    max_attempts: int,
    window_seconds: int,
    lockout_seconds: int,
) -> dict:
    """
    Check whether a login attempt should be blocked for this username or client IP.
    A block is triggered after `max_attempts` failed attempts inside `window_seconds`,
    and lasts `lockout_seconds` from the latest failed attempt in that scope.
    """
    normalized_username = username.strip()
    normalized_remote_addr = (remote_addr or "unknown").strip() or "unknown"
    now = time.time()
    window_cutoff = now - max(1, int(window_seconds))
    max_attempts = max(1, int(max_attempts))
    lockout_seconds = max(1, int(lockout_seconds))

    def _scope_retry_after(cur: sqlite3.Cursor, column_name: str, value: str) -> float:
        rows = cur.execute(
            f"""
            SELECT attempted_at
            FROM teacher_login_attempts
            WHERE success = 0 AND {column_name} = ? AND attempted_at >= ?
            ORDER BY attempted_at DESC
            LIMIT ?
            """,
            (value, window_cutoff, max_attempts),
        ).fetchall()

        if len(rows) < max_attempts:
            return 0.0

        latest_failure = rows[0]["attempted_at"]
        return max(0.0, (latest_failure + lockout_seconds) - now)

    conn = get_connection()
    cur = conn.cursor()
    username_retry_after = _scope_retry_after(cur, "username", normalized_username)
    remote_retry_after = _scope_retry_after(cur, "remote_addr", normalized_remote_addr)
    conn.close(); _local.conn = None

    retry_after_seconds = int(max(username_retry_after, remote_retry_after))
    return {
        "blocked": retry_after_seconds > 0,
        "retry_after_seconds": retry_after_seconds,
        "scope": "username" if username_retry_after >= remote_retry_after else "remote_addr",
    }


def create_teacher_login_session(session_id: str, username: str):
    """Store a successful teacher dashboard login session."""
    conn = get_connection()
    conn.execute(
        """
        INSERT INTO teacher_login_sessions (session_id, username, login_at)
        VALUES (?, ?, ?)
        """,
        (session_id, username, time.time()),
    )
    conn.commit()
    conn.close(); _local.conn = None


def close_teacher_login_session(session_id: str):
    """Mark a teacher dashboard session as logged out."""
    conn = get_connection()
    conn.execute(
        "UPDATE teacher_login_sessions SET logout_at = ? WHERE session_id = ? AND logout_at IS NULL",
        (time.time(), session_id),
    )
    conn.commit()
    conn.close(); _local.conn = None


def get_recent_teacher_access(limit: int = 50) -> list[dict]:
    """Fetch recent teacher dashboard access sessions."""
    conn = get_connection()
    rows = conn.execute(
        """
        SELECT session_id, username, login_at, logout_at
        FROM teacher_login_sessions
        ORDER BY login_at DESC
        LIMIT ?
        """,
        (max(1, int(limit)),),
    ).fetchall()
    conn.close(); _local.conn = None
    return [dict(r) for r in rows]


def _build_session_recommendations(
    severity_summary: dict[str, int],
    flag_counts: dict[str, int],
    total_logs: int,
    total_alerts: int,
) -> list[str]:
    recommendations: list[str] = []

    if severity_summary.get("CRITICAL", 0) > 0:
        recommendations.append("Review critical alerts first and verify whether any student requires immediate intervention.")
    if flag_counts.get("usb_events", 0) > 0:
        recommendations.append("Inspect USB activity closely, especially removable storage mounts or unknown HID devices.")
    if flag_counts.get("screenshot_events", 0) > 0:
        recommendations.append("Review screenshot or snip activity for possible policy violations during the session.")
    if flag_counts.get("blocked_browser_events", 0) > 0:
        recommendations.append("Follow up on restricted browsing and confirm whether those sites were allowed for the class.")
    if flag_counts.get("terminal_events", 0) > 0 and severity_summary.get("HIGH", 0) > 0:
        recommendations.append("Correlate terminal usage with high-severity alerts to rule out unauthorized commands or tools.")
    if total_alerts == 0 and total_logs > 0:
        recommendations.append("No alerts were raised during this session, but the raw event timeline is available for audit review.")
    if total_logs == 0:
        recommendations.append("No activity was captured in this login window. Verify the manager, agents, and monitoring services are running.")

    return recommendations[:5]


def generate_session_report(session_id: str) -> dict:
    """
    Generate a report of activity during a teacher login session.
    Returns summary of alerts and logs captured during the session window.
    """
    conn = get_connection()

    # Get session timestamps
    session = conn.execute(
        "SELECT username, login_at, logout_at FROM teacher_login_sessions WHERE session_id = ?",
        (session_id,),
    ).fetchone()

    if not session:
        conn.close()
        _local.conn = None
        return {
            "status": "not_found",
            "session_id": session_id,
            "error": "Session not found"
        }

    username = session["username"]
    login_at = session["login_at"]
    logout_at = session["logout_at"] or time.time()

    severity_rows = conn.execute(
        """
        SELECT severity, COUNT(*) as count
        FROM alerts
        WHERE timestamp BETWEEN ? AND ?
        GROUP BY severity
        """,
        (login_at, logout_at)
    ).fetchall()

    rule_rows = conn.execute(
        """
        SELECT severity, rule_id, rule_name, COUNT(*) as count, MAX(timestamp) as last_seen
        FROM alerts
        WHERE timestamp BETWEEN ? AND ?
        GROUP BY severity, rule_id, rule_name
        ORDER BY count DESC, last_seen DESC
        LIMIT 25
        """,
        (login_at, logout_at)
    ).fetchall()

    alert_rows = conn.execute(
        """
        SELECT id, severity, rule_id, rule_name, hostname, matched_log, acknowledged, timestamp
        FROM alerts
        WHERE timestamp BETWEEN ? AND ?
        ORDER BY timestamp DESC
        LIMIT 120
        """,
        (login_at, logout_at)
    ).fetchall()

    log_rows = conn.execute(
        """
        SELECT id, hostname, source, raw_log, timestamp
        FROM logs
        WHERE timestamp BETWEEN ? AND ?
        ORDER BY timestamp DESC
        LIMIT 180
        """,
        (login_at, logout_at)
    ).fetchall()

    host_alert_rows = conn.execute(
        """
        SELECT hostname, COUNT(*) as alert_count
        FROM alerts
        WHERE timestamp BETWEEN ? AND ?
        GROUP BY hostname
        ORDER BY alert_count DESC
        LIMIT 20
        """,
        (login_at, logout_at)
    ).fetchall()

    host_log_rows = conn.execute(
        """
        SELECT hostname, COUNT(*) as log_count
        FROM logs
        WHERE timestamp BETWEEN ? AND ?
        GROUP BY hostname
        ORDER BY log_count DESC
        LIMIT 20
        """,
        (login_at, logout_at)
    ).fetchall()

    sources = conn.execute(
        """
        SELECT source, COUNT(*) as log_count
        FROM logs
        WHERE timestamp BETWEEN ? AND ?
        GROUP BY source
        ORDER BY log_count DESC
        """,
        (login_at, logout_at)
    ).fetchall()

    flag_row = conn.execute(
        """
        SELECT
            COALESCE(SUM(CASE WHEN source = 'SCREENSHOT' OR raw_log LIKE '%SCREENSHOT_TAKEN%' THEN 1 ELSE 0 END), 0) AS screenshot_events,
            COALESCE(SUM(CASE WHEN source IN ('USB', 'LAB_USB') OR raw_log LIKE '%LAB_USB_INSERT%' OR raw_log LIKE '%USB_ATTACH%' THEN 1 ELSE 0 END), 0) AS usb_events,
            COALESCE(SUM(CASE WHEN raw_log LIKE '%SUSPICIOUS_WINDOW%' THEN 1 ELSE 0 END), 0) AS suspicious_window_events,
            COALESCE(SUM(CASE WHEN raw_log LIKE '%BROWSER_BLOCKED%' THEN 1 ELSE 0 END), 0) AS blocked_browser_events,
            COALESCE(SUM(CASE WHEN source IN ('POWERSHELL', 'SHELL') OR raw_log LIKE '%TERMINAL_COMMAND%' OR raw_log LIKE '%SHELL_COMMAND%' THEN 1 ELSE 0 END), 0) AS terminal_events
        FROM logs
        WHERE timestamp BETWEEN ? AND ?
        """,
        (login_at, logout_at)
    ).fetchone()

    conn.close()
    _local.conn = None

    session_duration_seconds = logout_at - login_at
    session_duration_minutes = session_duration_seconds / 60
    severity_summary = {row["severity"]: row["count"] for row in severity_rows}
    total_alerts = sum(row["count"] for row in severity_rows)
    total_logs = sum(row["log_count"] for row in sources)
    flag_counts = dict(flag_row) if flag_row else {
        "screenshot_events": 0,
        "usb_events": 0,
        "suspicious_window_events": 0,
        "blocked_browser_events": 0,
        "terminal_events": 0,
    }

    host_activity: dict[str, dict] = {}
    for row in host_log_rows:
        host_activity[row["hostname"]] = {
            "hostname": row["hostname"],
            "log_count": row["log_count"],
            "alert_count": 0,
        }
    for row in host_alert_rows:
        entry = host_activity.setdefault(
            row["hostname"],
            {
                "hostname": row["hostname"],
                "log_count": 0,
                "alert_count": 0,
            },
        )
        entry["alert_count"] = row["alert_count"]

    machine_activity = sorted(
        host_activity.values(),
        key=lambda item: (item["alert_count"], item["log_count"], item["hostname"]),
        reverse=True,
    )

    timeline = [
        {
            "kind": "alert",
            "timestamp": row["timestamp"],
            "hostname": row["hostname"],
            "source": "ALERT",
            "severity": row["severity"],
            "title": row["rule_name"],
            "detail": row["matched_log"],
        }
        for row in alert_rows
    ] + [
        {
            "kind": "event",
            "timestamp": row["timestamp"],
            "hostname": row["hostname"],
            "source": row["source"],
            "severity": None,
            "title": row["source"],
            "detail": row["raw_log"],
        }
        for row in log_rows
    ]
    timeline.sort(key=lambda item: item["timestamp"], reverse=True)
    timeline = timeline[:220]

    recommendations = _build_session_recommendations(
        severity_summary=severity_summary,
        flag_counts=flag_counts,
        total_logs=total_logs,
        total_alerts=total_alerts,
    )

    return {
        "status": "success",
        "session_id": session_id,
        "username": username,
        "login_time": login_at,
        "logout_time": logout_at,
        "duration_minutes": round(session_duration_minutes, 2),
        "duration_seconds": session_duration_seconds,
        "alerts": [
            {
                "severity": row["severity"],
                "rule": row["rule_name"],
                "count": row["count"],
                "last_seen": row["last_seen"],
            }
            for row in rule_rows
        ],
        "severity_summary": severity_summary,
        "machines_with_alerts": [
            {
                "hostname": row["hostname"],
                "alert_count": row["alert_count"]
            }
            for row in host_alert_rows
        ],
        "machine_activity": machine_activity,
        "activity_sources": [
            {
                "source": row["source"],
                "log_count": row["log_count"]
            }
            for row in sources
        ],
        "flag_counts": flag_counts,
        "recommendations": recommendations,
        "recent_alerts": [
            {
                "id": row["id"],
                "severity": row["severity"],
                "rule_id": row["rule_id"],
                "rule_name": row["rule_name"],
                "hostname": row["hostname"],
                "matched_log": row["matched_log"],
                "acknowledged": bool(row["acknowledged"]),
                "timestamp": row["timestamp"],
            }
            for row in alert_rows
        ],
        "recent_events": [
            {
                "id": row["id"],
                "hostname": row["hostname"],
                "source": row["source"],
                "raw_log": row["raw_log"],
                "timestamp": row["timestamp"],
            }
            for row in log_rows
        ],
        "timeline": timeline,
        "display_limits": {
            "alerts": len(alert_rows),
            "events": len(log_rows),
            "timeline": len(timeline),
        },
        "total_alerts": total_alerts,
        "total_logs": total_logs,
    }
