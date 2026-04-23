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
import json
import re

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


def _normalize_role(role: str | None) -> str:
    return "admin" if str(role or "").strip().lower() == "admin" else "teacher"


def _normalize_allowed_hostnames(allowed_hostnames: list[str] | None) -> list[str] | None:
    if allowed_hostnames is None:
        return None
    normalized = sorted({str(item).strip() for item in allowed_hostnames if str(item).strip()})
    if "*" in normalized:
        return None
    return normalized


def _serialize_allowed_hostnames(allowed_hostnames: list[str] | None) -> str:
    normalized = _normalize_allowed_hostnames(allowed_hostnames)
    if normalized is None:
        return json.dumps(["*"])
    return json.dumps(normalized)


def _deserialize_allowed_hostnames(raw_value: str | None) -> list[str]:
    if not raw_value:
        return []
    try:
        data = json.loads(raw_value)
        if isinstance(data, list):
            normalized = sorted({str(item).strip() for item in data if str(item).strip()})
            return ["*"] if "*" in normalized else normalized
    except Exception:
        pass

    fallback = [part.strip() for part in str(raw_value).split("|") if part.strip()]
    return ["*"] if "*" in fallback else fallback


def _normalize_alert_log(raw_log: str | None) -> str:
    if not raw_log:
        return ""
    return re.sub(r"^\[.*?\]\s*", "", str(raw_log)).strip()


def _append_hostname_scope(query: str, params: list, column_name: str, allowed_hostnames: list[str] | None) -> tuple[str, list]:
    normalized = _normalize_allowed_hostnames(allowed_hostnames)
    if normalized is None:
        return query, params
    if not normalized:
        return query + " AND 1=0", params
    placeholders = ",".join("?" for _ in normalized)
    query += f" AND {column_name} IN ({placeholders})"
    params.extend(normalized)
    return query, params


def _teacher_row_to_profile(row: sqlite3.Row | None) -> dict | None:
    if not row:
        return None
    role = _normalize_role(row["role"] if "role" in row.keys() else "teacher")
    allowed_hostnames = _deserialize_allowed_hostnames(row["allowed_hostnames"] if "allowed_hostnames" in row.keys() else "")
    if role == "admin":
        allowed_hostnames = ["*"]
    return {
        "username": row["username"],
        "role": role,
        "allowed_hostnames": allowed_hostnames,
    }


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

    # --- Agent control commands queue ---
    cur.execute("""
        CREATE TABLE IF NOT EXISTS agent_commands (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id TEXT NOT NULL,
            hostname TEXT NOT NULL,
            requested_by TEXT NOT NULL,
            action TEXT NOT NULL,
            payload TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'queued',
            result_message TEXT,
            requested_at REAL NOT NULL,
            dispatched_at REAL,
            completed_at REAL
        )
    """)

    # --- Dashboard teacher users ---
    cur.execute("""
        CREATE TABLE IF NOT EXISTS teacher_users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'teacher',
            allowed_hostnames TEXT NOT NULL DEFAULT '[]',
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

    teacher_user_columns = {
        row["name"]
        for row in cur.execute("PRAGMA table_info(teacher_users)").fetchall()
    }
    if "role" not in teacher_user_columns:
        cur.execute("ALTER TABLE teacher_users ADD COLUMN role TEXT NOT NULL DEFAULT 'teacher'")
    if "allowed_hostnames" not in teacher_user_columns:
        cur.execute("ALTER TABLE teacher_users ADD COLUMN allowed_hostnames TEXT NOT NULL DEFAULT '[]'")

    # --- Indexes for faster queries (critical for 60+ agents) ---
    cur.execute("CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs(timestamp DESC)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_logs_agent ON logs(agent_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp DESC)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_alerts_ack ON alerts(acknowledged)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_agent_commands_agent_status ON agent_commands(agent_id, status, requested_at)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_agent_commands_status ON agent_commands(status)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_agent_commands_requested_at ON agent_commands(requested_at DESC)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_teacher_login_username ON teacher_login_sessions(username)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_teacher_login_login_at ON teacher_login_sessions(login_at DESC)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_teacher_attempt_username ON teacher_login_attempts(username)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_teacher_attempt_remote_addr ON teacher_login_attempts(remote_addr)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_teacher_attempt_attempted_at ON teacher_login_attempts(attempted_at DESC)")

    # Seed teacher accounts and keep configured credentials in sync with SQLite.
    now = time.time()
    existing_teacher_rows = cur.execute(
        "SELECT username, password_hash, role, allowed_hostnames FROM teacher_users"
    ).fetchall()
    existing_teacher_profiles = {
        row["username"]: {
            "password_hash": row["password_hash"],
            "role": row["role"] if "role" in row.keys() else "teacher",
            "allowed_hostnames": row["allowed_hostnames"] if "allowed_hostnames" in row.keys() else "[]",
        }
        for row in existing_teacher_rows
    }

    inserted_accounts = 0
    updated_accounts = 0
    for account in TEACHER_ACCOUNTS:
        username = account["username"]
        password = account["password"]
        role = _normalize_role(account.get("role"))
        allowed_hostnames = ["*"] if role == "admin" else account.get("allowed_hostnames", [])
        serialized_allowed_hostnames = _serialize_allowed_hostnames(allowed_hostnames)

        stored_profile = existing_teacher_profiles.get(username)
        if stored_profile is None:
            cur.execute(
                """
                INSERT INTO teacher_users (username, password_hash, role, allowed_hostnames, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (username, hash_password(password), role, serialized_allowed_hostnames, now),
            )
            inserted_accounts += 1
            continue

        updates: list[str] = []
        params: list = []
        if not verify_password(password, stored_profile["password_hash"]):
            updates.append("password_hash = ?")
            params.append(hash_password(password))
        if _normalize_role(stored_profile["role"]) != role:
            updates.append("role = ?")
            params.append(role)
        if stored_profile["allowed_hostnames"] != serialized_allowed_hostnames:
            updates.append("allowed_hostnames = ?")
            params.append(serialized_allowed_hostnames)

        if updates:
            cur.execute(
                f"UPDATE teacher_users SET {', '.join(updates)} WHERE username = ?",
                (*params, username),
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


def get_all_agents(allowed_hostnames: list[str] | None = None) -> list[dict]:
    conn = get_connection()
    query = "SELECT * FROM agents WHERE 1=1"
    params: list = []
    query, params = _append_hostname_scope(query, params, "hostname", allowed_hostnames)
    query += " ORDER BY last_seen DESC"
    rows = conn.execute(query, tuple(params)).fetchall()
    conn.close(); _local.conn = None
    return [dict(r) for r in rows]


def get_agent_by_id(agent_id: str) -> dict | None:
    conn = get_connection()
    row = conn.execute(
        "SELECT * FROM agents WHERE agent_id = ?",
        (agent_id,),
    ).fetchone()
    conn.close(); _local.conn = None
    return dict(row) if row else None


def queue_agent_command(
    agent_id: str,
    hostname: str,
    requested_by: str,
    action: str,
    payload: dict,
) -> dict:
    conn = get_connection()
    requested_at = time.time()
    payload_json = json.dumps(payload)
    cur = conn.execute(
        """
        INSERT INTO agent_commands (
            agent_id, hostname, requested_by, action, payload, status, requested_at
        )
        VALUES (?, ?, ?, ?, ?, 'queued', ?)
        """,
        (agent_id, hostname, requested_by, action, payload_json, requested_at),
    )
    command_id = cur.lastrowid
    conn.commit()
    row = conn.execute(
        """
        SELECT id, agent_id, hostname, requested_by, action, payload, status, requested_at
        FROM agent_commands
        WHERE id = ?
        """,
        (command_id,),
    ).fetchone()
    conn.close(); _local.conn = None
    return dict(row) if row else {}


def claim_queued_agent_commands(agent_id: str, limit: int = 5) -> list[dict]:
    conn = get_connection()
    cur = conn.cursor()
    rows = cur.execute(
        """
        SELECT id, agent_id, hostname, requested_by, action, payload, status, requested_at
        FROM agent_commands
        WHERE agent_id = ? AND status = 'queued'
        ORDER BY requested_at ASC
        LIMIT ?
        """,
        (agent_id, max(1, int(limit))),
    ).fetchall()

    claimed: list[dict] = []
    now = time.time()
    for row in rows:
        updated = cur.execute(
            """
            UPDATE agent_commands
            SET status = 'dispatching', dispatched_at = ?
            WHERE id = ? AND status = 'queued'
            """,
            (now, row["id"]),
        )
        if not updated.rowcount:
            continue

        row_payload = row["payload"]
        try:
            parsed_payload = json.loads(row_payload) if row_payload else {}
        except Exception:
            parsed_payload = {}

        claimed.append(
            {
                "id": row["id"],
                "agent_id": row["agent_id"],
                "hostname": row["hostname"],
                "requested_by": row["requested_by"],
                "action": row["action"],
                "payload": parsed_payload,
                "status": "dispatching",
                "requested_at": row["requested_at"],
                "dispatched_at": now,
            }
        )

    conn.commit()
    conn.close(); _local.conn = None
    return claimed


def mark_agent_command_sent(command_id: int):
    conn = get_connection()
    conn.execute(
        """
        UPDATE agent_commands
        SET status = 'sent', dispatched_at = COALESCE(dispatched_at, ?)
        WHERE id = ? AND status IN ('queued', 'dispatching')
        """,
        (time.time(), command_id),
    )
    conn.commit()
    conn.close(); _local.conn = None


def mark_agent_command_failed(command_id: int, result_message: str):
    conn = get_connection()
    conn.execute(
        """
        UPDATE agent_commands
        SET status = 'failed', result_message = ?, completed_at = ?
        WHERE id = ?
        """,
        (result_message[:500], time.time(), command_id),
    )
    conn.commit()
    conn.close(); _local.conn = None


def complete_agent_command(command_id: int, success: bool, result_message: str = ""):
    conn = get_connection()
    conn.execute(
        """
        UPDATE agent_commands
        SET status = ?, result_message = ?, completed_at = ?
        WHERE id = ?
        """,
        ("completed" if success else "failed", (result_message or "")[:500], time.time(), command_id),
    )
    conn.commit()
    conn.close(); _local.conn = None


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


def get_logs(limit: int = 100, agent_id: str = None, allowed_hostnames: list[str] | None = None) -> list[dict]:
    """Fetch recent logs, optionally filtered by agent."""
    conn = get_connection()
    params: list = []
    query = "SELECT * FROM logs WHERE 1=1"
    if agent_id:
        query += " AND agent_id=?"
        params.append(agent_id)
    query, params = _append_hostname_scope(query, params, "hostname", allowed_hostnames)
    query += " ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)
    rows = conn.execute(query, tuple(params)).fetchall()
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


def get_alerts(
    limit: int = 100,
    severity: str = None,
    date_str: str = None,
    hostname: str = None,
    allowed_hostnames: list[str] | None = None,
) -> list[dict]:
    """Fetch recent alerts, optionally filtered by severity and date (YYYY-MM-DD)."""
    conn = get_connection()
    
    query = "SELECT * FROM alerts WHERE 1=1"
    params: list = []
    
    if severity:
        query += " AND severity=?"
        params.append(severity)

    if hostname:
        query += " AND hostname=?"
        params.append(hostname)
        
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

    query, params = _append_hostname_scope(query, params, "hostname", allowed_hostnames)
            
    query += " ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)
    
    rows = conn.execute(query, tuple(params)).fetchall()
    conn.close(); _local.conn = None
    return [dict(r) for r in rows]


def acknowledge_alert(alert_id: int, allowed_hostnames: list[str] | None = None) -> bool:
    """Mark an alert (and duplicates within a short window) as acknowledged."""
    conn = get_connection()
    base_query = "SELECT id, hostname, matched_log, timestamp FROM alerts WHERE id=?"
    base_params: list = [alert_id]
    base_query, base_params = _append_hostname_scope(base_query, base_params, "hostname", allowed_hostnames)
    row = conn.execute(base_query, tuple(base_params)).fetchone()
    if not row:
        conn.close(); _local.conn = None
        return False

    target_log = _normalize_alert_log(row["matched_log"])
    window_seconds = 300
    start_ts = row["timestamp"] - window_seconds
    end_ts = row["timestamp"] + window_seconds

    related_ids = [row["id"]]
    if target_log:
        candidates_query = """
            SELECT id, matched_log
            FROM alerts
            WHERE hostname = ?
              AND acknowledged = 0
              AND timestamp BETWEEN ? AND ?
        """
        candidates_params: list = [row["hostname"], start_ts, end_ts]
        candidates_query, candidates_params = _append_hostname_scope(
            candidates_query, candidates_params, "hostname", allowed_hostnames
        )
        candidates = conn.execute(candidates_query, tuple(candidates_params)).fetchall()
        related_ids = [
            candidate["id"]
            for candidate in candidates
            if _normalize_alert_log(candidate["matched_log"]) == target_log
        ] or [row["id"]]

    placeholders = ",".join("?" for _ in related_ids)
    update_query = f"UPDATE alerts SET acknowledged=1 WHERE id IN ({placeholders})"
    cur = conn.execute(update_query, tuple(related_ids))
    conn.commit()
    conn.close(); _local.conn = None
    return bool(cur.rowcount)


def get_alert_counts(allowed_hostnames: list[str] | None = None) -> dict:
    """Get alert counts grouped by severity (for dashboard stats)."""
    conn = get_connection()
    query = """
        SELECT severity, COUNT(*) as count
        FROM alerts
        WHERE acknowledged = 0
    """
    params: list = []
    query, params = _append_hostname_scope(query, params, "hostname", allowed_hostnames)
    query += """
        GROUP BY severity
    """
    rows = conn.execute(query, tuple(params)).fetchall()
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


def authenticate_teacher(username: str, password: str) -> dict | None:
    """Validate a dashboard teacher username/password pair and return the canonical account profile."""
    conn = get_connection()
    row = conn.execute(
        "SELECT username, password_hash, role, allowed_hostnames FROM teacher_users WHERE lower(username) = lower(?)",
        (username.strip(),),
    ).fetchone()
    conn.close(); _local.conn = None
    if not row:
        return None
    if verify_password(password, row["password_hash"]):
        return _teacher_row_to_profile(row)
    return None


def get_teacher_user(username: str) -> dict | None:
    """Fetch a teacher account profile for RBAC checks."""
    conn = get_connection()
    row = conn.execute(
        "SELECT username, role, allowed_hostnames FROM teacher_users WHERE lower(username) = lower(?)",
        (username.strip(),),
    ).fetchone()
    conn.close(); _local.conn = None
    return _teacher_row_to_profile(row)


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


def get_recent_teacher_access(limit: int = 50, viewer_username: str | None = None, is_admin: bool = False) -> list[dict]:
    """Fetch recent teacher dashboard access sessions."""
    conn = get_connection()
    params: list = []
    query = """
        SELECT session_id, username, login_at, logout_at
        FROM teacher_login_sessions
        WHERE 1=1
    """
    if viewer_username and not is_admin:
        query += " AND username = ?"
        params.append(viewer_username)
    query += """
        ORDER BY login_at DESC
        LIMIT ?
    """
    params.append(max(1, int(limit)))
    rows = conn.execute(query, tuple(params)).fetchall()
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


def generate_session_report(
    session_id: str,
    viewer_username: str | None = None,
    is_admin: bool = False,
    allowed_hostnames: list[str] | None = None,
) -> dict:
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
    if viewer_username and not is_admin and username != viewer_username:
        conn.close()
        _local.conn = None
        return {
            "status": "forbidden",
            "session_id": session_id,
            "error": "You are not allowed to view another user's session report.",
        }

    login_at = session["login_at"]
    logout_at = session["logout_at"] or time.time()

    severity_query = """
        SELECT severity, COUNT(*) as count
        FROM alerts
        WHERE timestamp BETWEEN ? AND ?
    """
    severity_params: list = [login_at, logout_at]
    severity_query, severity_params = _append_hostname_scope(severity_query, severity_params, "hostname", allowed_hostnames)
    severity_query += " GROUP BY severity"
    severity_rows = conn.execute(severity_query, tuple(severity_params)).fetchall()

    rule_query = """
        SELECT severity, rule_id, rule_name, COUNT(*) as count, MAX(timestamp) as last_seen
        FROM alerts
        WHERE timestamp BETWEEN ? AND ?
    """
    rule_params: list = [login_at, logout_at]
    rule_query, rule_params = _append_hostname_scope(rule_query, rule_params, "hostname", allowed_hostnames)
    rule_query += """
        GROUP BY severity, rule_id, rule_name
        ORDER BY count DESC, last_seen DESC
        LIMIT 25
    """
    rule_rows = conn.execute(rule_query, tuple(rule_params)).fetchall()

    alert_query = """
        SELECT id, severity, rule_id, rule_name, hostname, matched_log, acknowledged, timestamp
        FROM alerts
        WHERE timestamp BETWEEN ? AND ?
    """
    alert_params: list = [login_at, logout_at]
    alert_query, alert_params = _append_hostname_scope(alert_query, alert_params, "hostname", allowed_hostnames)
    alert_query += " ORDER BY timestamp DESC LIMIT 120"
    alert_rows = conn.execute(alert_query, tuple(alert_params)).fetchall()

    log_query = """
        SELECT id, hostname, source, raw_log, timestamp
        FROM logs
        WHERE timestamp BETWEEN ? AND ?
    """
    log_params: list = [login_at, logout_at]
    log_query, log_params = _append_hostname_scope(log_query, log_params, "hostname", allowed_hostnames)
    log_query += " ORDER BY timestamp DESC LIMIT 180"
    log_rows = conn.execute(log_query, tuple(log_params)).fetchall()

    host_alert_query = """
        SELECT hostname, COUNT(*) as alert_count
        FROM alerts
        WHERE timestamp BETWEEN ? AND ?
    """
    host_alert_params: list = [login_at, logout_at]
    host_alert_query, host_alert_params = _append_hostname_scope(host_alert_query, host_alert_params, "hostname", allowed_hostnames)
    host_alert_query += """
        GROUP BY hostname
        ORDER BY alert_count DESC
        LIMIT 20
    """
    host_alert_rows = conn.execute(host_alert_query, tuple(host_alert_params)).fetchall()

    host_log_query = """
        SELECT hostname, COUNT(*) as log_count
        FROM logs
        WHERE timestamp BETWEEN ? AND ?
    """
    host_log_params: list = [login_at, logout_at]
    host_log_query, host_log_params = _append_hostname_scope(host_log_query, host_log_params, "hostname", allowed_hostnames)
    host_log_query += """
        GROUP BY hostname
        ORDER BY log_count DESC
        LIMIT 20
    """
    host_log_rows = conn.execute(host_log_query, tuple(host_log_params)).fetchall()

    sources_query = """
        SELECT source, COUNT(*) as log_count
        FROM logs
        WHERE timestamp BETWEEN ? AND ?
    """
    sources_params: list = [login_at, logout_at]
    sources_query, sources_params = _append_hostname_scope(sources_query, sources_params, "hostname", allowed_hostnames)
    sources_query += """
        GROUP BY source
        ORDER BY log_count DESC
    """
    sources = conn.execute(sources_query, tuple(sources_params)).fetchall()

    flag_query = """
        SELECT
            COALESCE(SUM(CASE WHEN source = 'SCREENSHOT' OR raw_log LIKE '%SCREENSHOT_TAKEN%' THEN 1 ELSE 0 END), 0) AS screenshot_events,
            COALESCE(SUM(CASE WHEN source IN ('USB', 'LAB_USB') OR raw_log LIKE '%LAB_USB_INSERT%' OR raw_log LIKE '%USB_ATTACH%' THEN 1 ELSE 0 END), 0) AS usb_events,
            COALESCE(SUM(CASE WHEN raw_log LIKE '%SUSPICIOUS_WINDOW%' THEN 1 ELSE 0 END), 0) AS suspicious_window_events,
            COALESCE(SUM(CASE WHEN raw_log LIKE '%BROWSER_BLOCKED%' THEN 1 ELSE 0 END), 0) AS blocked_browser_events,
            COALESCE(SUM(CASE WHEN source IN ('POWERSHELL', 'SHELL') OR raw_log LIKE '%TERMINAL_COMMAND%' OR raw_log LIKE '%SHELL_COMMAND%' THEN 1 ELSE 0 END), 0) AS terminal_events
        FROM logs
        WHERE timestamp BETWEEN ? AND ?
    """
    flag_params: list = [login_at, logout_at]
    flag_query, flag_params = _append_hostname_scope(flag_query, flag_params, "hostname", allowed_hostnames)
    flag_row = conn.execute(flag_query, tuple(flag_params)).fetchone()

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
