import os
import sys
import secrets
import json
import asyncio
from datetime import datetime
from contextlib import asynccontextmanager
from html import escape
from fastapi import FastAPI, Query, Request, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
import uvicorn

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
from database.db import (
    init_db,
    get_all_agents,
    get_alerts,
    get_alert_counts,
    acknowledge_alert,
    get_logs,
    get_agent_by_id,
    queue_agent_command,
)
from database.db import prune_old_data
from database.db import (
    authenticate_teacher,
    create_teacher_login_session,
    close_teacher_login_session,
    get_teacher_user,
    get_recent_teacher_access,
    generate_session_report,
    get_teacher_login_rate_limit_status,
    record_teacher_login_attempt,
)
from shared.config import (
    API_HOST,
    API_PORT,
    DASHBOARD_AUTO_RELOAD,
    DASHBOARD_SESSION_SECRET,
    DASHBOARD_LOGIN_RATE_LIMIT_ATTEMPTS,
    DASHBOARD_LOGIN_RATE_LIMIT_WINDOW_SECONDS,
    DASHBOARD_LOGIN_RATE_LIMIT_LOCKOUT_SECONDS,
)
from dashboard.teacher_insights import build_teacher_insights, answer_teacher_query, build_class_period_report_html

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield

app = FastAPI(title="SOC Platform API", lifespan=lifespan)

app.add_middleware(
    SessionMiddleware,
    secret_key=DASHBOARD_SESSION_SECRET,
    max_age=60 * 60 * 12,  # 12 hours
    same_site="lax",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DASHBOARD_PATH = os.path.join(os.path.dirname(__file__), "templates", "index.html")
TERMINATE_PROCESS_TARGETS = {"chrome", "firefox", "brave", "terminal"}


def _is_authenticated(request: Request) -> bool:
    return bool(request.session.get("auth_ok"))


def require_auth(request: Request):
    if not _is_authenticated(request):
        raise PermissionError("Unauthorized")


def _current_user(request: Request) -> dict | None:
    if not _is_authenticated(request):
        return None

    username = request.session.get("teacher_username", "")
    role = str(request.session.get("teacher_role", "teacher") or "teacher").lower()
    allowed_hostnames = request.session.get("teacher_allowed_hostnames")
    if not username:
        return None

    if not isinstance(allowed_hostnames, list):
        profile = get_teacher_user(username)
        if profile:
            return profile
        return {
            "username": username,
            "role": role,
            "allowed_hostnames": [],
        }

    return {
        "username": username,
        "role": "admin" if role == "admin" else "teacher",
        "allowed_hostnames": allowed_hostnames,
    }


def _allowed_hostnames_for_user(user: dict | None) -> list[str] | None:
    if not user:
        return []
    allowed_hostnames = user.get("allowed_hostnames") or []
    if user.get("role") == "admin" or "*" in allowed_hostnames:
        return None
    return allowed_hostnames


def _ensure_hostname_allowed(user: dict | None, hostname: str | None):
    if not hostname:
        return
    allowed_hostnames = _allowed_hostnames_for_user(user)
    if allowed_hostnames is None:
        return
    if hostname not in allowed_hostnames:
        raise HTTPException(status_code=403, detail="You are not allowed to access this machine.")


def _scope_label(user: dict | None) -> str:
    if not user:
        return "restricted"
    allowed_hostnames = _allowed_hostnames_for_user(user)
    if allowed_hostnames is None:
        return "all machines"
    if not allowed_hostnames:
        return "no machine scope assigned"
    if len(allowed_hostnames) == 1:
        return allowed_hostnames[0]
    return f"{len(allowed_hostnames)} machines"


def _require_admin(user: dict | None):
    if not user or user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin role required.")


def _login_page(error: str = "") -> str:
    error_html = f"<div class='error'>{error}</div>" if error else ""
    return f"""
    <!doctype html>
    <html>
    <head>
      <meta charset=\"utf-8\" />
      <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\" />
      <title>Lab Monitor - Staff Portal</title>
      <link rel="preconnect" href="https://fonts.googleapis.com">
      <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
      <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
      <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css">
      <style>
        :root {{
          --bg:#0b1220;
          --bg-soft:#111827;
          --panel:#0f172a;
          --line:#334155;
          --text:#e2e8f0;
          --muted:#94a3b8;
          --brand:#3b82f6;
          --brand-2:#2563eb;
          --danger:#ef4444;
        }}
        * {{ box-sizing:border-box; }}
        body {{
          margin:0;
          font-family:'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif;
          color:var(--text);
          background:
            radial-gradient(circle at 10% 10%, rgba(59,130,246,.18), transparent 35%),
            radial-gradient(circle at 90% 20%, rgba(14,165,233,.16), transparent 30%),
            var(--bg);
        }}
        .wrap {{
          min-height:100vh;
          display:grid;
          grid-template-columns: 1.1fr .9fr;
        }}
        .hero {{
          padding:56px 64px;
          display:flex;
          flex-direction:column;
          justify-content:center;
        }}
        .hero-badge {{
          display:inline-flex;
          align-items:center;
          gap:8px;
          width:max-content;
          margin-bottom:20px;
          padding:8px 12px;
          font-size:12px;
          border-radius:999px;
          border:1px solid rgba(59,130,246,.45);
          background:rgba(59,130,246,.12);
          color:#bfdbfe;
          font-weight:600;
        }}
        .hero h1 {{
          margin:0 0 14px;
          font-size:42px;
          line-height:1.12;
          letter-spacing:-.6px;
        }}
        .hero p {{
          margin:0;
          max-width:560px;
          color:var(--muted);
          font-size:15px;
          line-height:1.75;
        }}
        .hero-metrics {{
          display:flex;
          gap:18px;
          margin-top:28px;
        }}
        .metric {{
          background:rgba(148,163,184,.09);
          border:1px solid rgba(148,163,184,.2);
          border-radius:12px;
          padding:10px 12px;
          min-width:120px;
        }}
        .metric .v {{ font-size:17px; font-weight:700; color:#dbeafe; }}
        .metric .k {{ font-size:11px; color:var(--muted); margin-top:2px; }}
        .panel {{
          border-left:1px solid rgba(148,163,184,.16);
          display:flex;
          align-items:center;
          justify-content:center;
          padding:24px;
        }}
        .card {{
          width:100%;
          max-width:390px;
          background:linear-gradient(180deg, rgba(15,23,42,.95), rgba(17,24,39,.97));
          border:1px solid var(--line);
          border-radius:16px;
          padding:22px;
          box-shadow:0 18px 60px rgba(2,6,23,.45);
        }}
        .brand {{
          display:flex;
          align-items:center;
          gap:10px;
          margin-bottom:10px;
          color:#bfdbfe;
          font-size:13px;
          font-weight:700;
          letter-spacing:.2px;
        }}
        h2 {{ margin:0 0 6px; font-size:24px; }}
        .muted {{ color:var(--muted); font-size:13px; margin-bottom:14px; }}
        .error {{
          color:#fecaca;
          background:rgba(239,68,68,.1);
          border:1px solid rgba(239,68,68,.35);
          border-radius:10px;
          padding:10px 12px;
          margin-bottom:12px;
          font-size:13px;
        }}
        label {{ display:block; margin:8px 0 6px; font-size:12px; color:#cbd5e1; font-weight:600; }}
        input {{
          width:100%;
          background:#0b1220;
          color:var(--text);
          border:1px solid var(--line);
          border-radius:10px;
          padding:11px 12px;
          margin-bottom:2px;
          outline:none;
          transition:border-color .15s, box-shadow .15s;
        }}
        input:focus {{
          border-color:#60a5fa;
          box-shadow:0 0 0 3px rgba(59,130,246,.2);
        }}
        button {{
          width:100%;
          margin-top:12px;
          background:linear-gradient(135deg,var(--brand),var(--brand-2));
          color:#fff;
          border:none;
          border-radius:10px;
          padding:11px;
          font-weight:700;
          letter-spacing:.2px;
          cursor:pointer;
        }}
        button:hover {{ filter:brightness(1.06); }}
        .foot {{
          margin-top:12px;
          color:var(--muted);
          font-size:11px;
          text-align:center;
        }}
        @media (max-width: 980px) {{
          .wrap {{ grid-template-columns:1fr; }}
          .hero {{ padding:30px 24px 10px; }}
          .hero h1 {{ font-size:30px; }}
          .panel {{ padding:18px 20px 26px; border-left:none; }}
        }}
        @media (max-width: 640px) {{
          .hero {{ padding:26px 18px 10px; }}
          .hero h1 {{ font-size:26px; }}
          .hero p {{ font-size:14px; }}
          .hero-metrics {{ flex-direction:column; gap:10px; }}
          .metric {{ min-width: unset; width: 100%; }}
          .panel {{ padding:16px; }}
          .card {{ padding:18px; }}
        }}
        @media (max-width: 480px) {{
          .hero h1 {{ font-size:24px; }}
          .hero-badge {{ font-size:11px; }}
          button {{ padding:10px; }}
        }}
      </style>
    </head>
    <body>
      <div class=\"wrap\">
        <section class=\"hero\">
          <div class=\"hero-badge\"><i class=\"fa-solid fa-shield-halved\"></i> SOC for Lab - Staff Portal</div>
          <h1>Secure classroom oversight for modern computer labs.</h1>
          <p>
            Monitor machine activity, review alerts in real time, and get class-level insights from one dashboard.
            This portal is restricted to authorized teaching staff.
          </p>
          <div class=\"hero-metrics\">
            <div class=\"metric\">
              <div class=\"v\"><i class=\"fa-solid fa-desktop\"></i> Live</div>
              <div class=\"k\">Machine visibility</div>
            </div>
            <div class=\"metric\">
              <div class=\"v\"><i class=\"fa-solid fa-bell\"></i> Instant</div>
              <div class=\"k\">Alert notifications</div>
            </div>
            <div class=\"metric\">
              <div class=\"v\"><i class=\"fa-solid fa-chart-line\"></i> AI</div>
              <div class=\"k\">Classroom insights</div>
            </div>
          </div>
        </section>
        <section class=\"panel\">
          <div class=\"card\">
            <div class=\"brand\"><i class=\"fa-solid fa-lock\"></i> Staff Authentication</div>
            <h2>Welcome back</h2>
            <div class=\"muted\">Sign in to open the monitoring dashboard</div>
            {error_html}
            <form method=\"post\" action=\"/login\">
              <label for=\"username\">Username</label>
              <input id=\"username\" type=\"text\" name=\"username\" placeholder=\"teacher01\" required />
              <label for=\"password\">Password</label>
              <input id=\"password\" type=\"password\" name=\"password\" placeholder=\"Enter password\" required />
              <button type=\"submit\"><i class=\"fa-solid fa-right-to-bracket\"></i> Sign In</button>
            </form>
            <div class=\"foot\">Authorized staff access only</div>
          </div>
        </section>
      </div>
    </body>
    </html>
    """


def _get_client_ip(request: Request) -> str:
    forwarded_for = request.headers.get("x-forwarded-for", "").strip()
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    if request.client and request.client.host:
        return request.client.host
    return "unknown"


def _format_retry_after(retry_after_seconds: int) -> str:
    minutes, seconds = divmod(max(0, retry_after_seconds), 60)
    if minutes and seconds:
        return f"{minutes}m {seconds}s"
    if minutes:
        return f"{minutes}m"
    return f"{seconds}s"


def _format_report_ts(timestamp: float | None) -> str:
    if not timestamp:
        return "N/A"
    return datetime.fromtimestamp(timestamp).strftime("%d %b %Y, %I:%M:%S %p")


def _format_duration(total_seconds: float) -> str:
    seconds = int(max(0, total_seconds or 0))
    hours, remainder = divmod(seconds, 3600)
    minutes, secs = divmod(remainder, 60)
    parts = []
    if hours:
        parts.append(f"{hours}h")
    if minutes:
        parts.append(f"{minutes}m")
    if secs or not parts:
        parts.append(f"{secs}s")
    return " ".join(parts)


def _clip_text(value: str, limit: int = 220) -> str:
    text = (value or "").strip()
    if len(text) <= limit:
        return text
    return text[: limit - 3].rstrip() + "..."


def _session_report_page(report: dict) -> str:
    severity_summary = report.get("severity_summary", {})
    activity_sources = report.get("activity_sources", [])
    machine_activity = report.get("machine_activity", [])
    recommendations = report.get("recommendations", [])
    recent_alerts = report.get("recent_alerts", [])
    timeline = report.get("timeline", [])
    flag_counts = report.get("flag_counts", {})

    severity_cards = "".join(
        f"""
        <div class="metric severity {sev.lower()}">
          <div class="metric-label">{escape(sev.title())}</div>
          <div class="metric-value">{severity_summary.get(sev, 0)}</div>
        </div>
        """
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
    )

    recommendations_html = "".join(
        f"<li>{escape(item)}</li>"
        for item in recommendations
    ) or "<li>No follow-up actions were suggested for this session.</li>"

    sources_html = "".join(
        f"""
        <tr>
          <td>{escape(item.get('source', 'Unknown'))}</td>
          <td>{item.get('log_count', 0)}</td>
        </tr>
        """
        for item in activity_sources[:12]
    ) or "<tr><td colspan='2'>No event sources recorded.</td></tr>"

    machines_html = "".join(
        f"""
        <tr>
          <td>{escape(item.get('hostname', 'Unknown'))}</td>
          <td>{item.get('alert_count', 0)}</td>
          <td>{item.get('log_count', 0)}</td>
        </tr>
        """
        for item in machine_activity[:15]
    ) or "<tr><td colspan='3'>No machine activity recorded.</td></tr>"

    alerts_html = "".join(
        f"""
        <tr>
          <td><span class="pill sev-{escape(item.get('severity', 'LOW').lower())}">{escape(item.get('severity', 'LOW'))}</span></td>
          <td>{escape(item.get('rule_name', 'Unknown rule'))}</td>
          <td>{escape(item.get('hostname', 'Unknown'))}</td>
          <td>{escape(_clip_text(item.get('matched_log', ''), 200))}</td>
          <td>{escape(_format_report_ts(item.get('timestamp')))}</td>
        </tr>
        """
        for item in recent_alerts[:80]
    ) or "<tr><td colspan='5'>No alerts were raised during this login window.</td></tr>"

    timeline_html = "".join(
        f"""
        <tr>
          <td>{escape(_format_report_ts(item.get('timestamp')))}</td>
          <td>{escape(item.get('kind', 'event').title())}</td>
          <td>{escape(item.get('severity') or item.get('source') or 'Event')}</td>
          <td>{escape(item.get('hostname', 'Unknown'))}</td>
          <td>{escape(_clip_text(item.get('detail', ''), 240))}</td>
        </tr>
        """
        for item in timeline[:180]
    ) or "<tr><td colspan='5'>No timeline entries available.</td></tr>"

    machine_count = len({item.get("hostname") for item in machine_activity if item.get("hostname")})

    return f"""
    <!doctype html>
    <html>
    <head>
      <meta charset="utf-8" />
      <meta name="viewport" content="width=device-width,initial-scale=1" />
      <title>Session Report - {escape(report.get('username', 'Teacher'))}</title>
      <style>
        :root {{
          --bg: #f3f6fb;
          --ink: #0f172a;
          --muted: #475569;
          --line: #d7deea;
          --panel: #ffffff;
          --brand: #1d4ed8;
          --brand-soft: #dbeafe;
          --critical: #b91c1c;
          --high: #dc2626;
          --medium: #d97706;
          --low: #0f766e;
        }}
        * {{ box-sizing: border-box; }}
        body {{
          margin: 0;
          background:
            radial-gradient(circle at top left, rgba(29,78,216,.1), transparent 28%),
            linear-gradient(180deg, #f8fbff 0%, var(--bg) 100%);
          color: var(--ink);
          font-family: "Segoe UI", Arial, sans-serif;
        }}
        .page {{
          max-width: 1220px;
          margin: 0 auto;
          padding: 24px;
        }}
        .hero {{
          background: linear-gradient(135deg, #0f172a, #1d4ed8 60%, #38bdf8);
          color: #fff;
          border-radius: 20px;
          padding: 28px;
          box-shadow: 0 24px 60px rgba(15, 23, 42, .18);
        }}
        .eyebrow {{
          display: inline-block;
          background: rgba(255,255,255,.14);
          border: 1px solid rgba(255,255,255,.22);
          border-radius: 999px;
          padding: 6px 10px;
          font-size: 12px;
          letter-spacing: .2px;
          margin-bottom: 12px;
        }}
        h1 {{
          margin: 0 0 8px;
          font-size: 34px;
          line-height: 1.1;
        }}
        .hero p {{
          margin: 0;
          max-width: 860px;
          color: rgba(255,255,255,.9);
          line-height: 1.6;
        }}
        .hero-meta {{
          display: flex;
          flex-wrap: wrap;
          gap: 10px 18px;
          margin-top: 18px;
          color: rgba(255,255,255,.92);
          font-size: 14px;
        }}
        .actions {{
          display: flex;
          gap: 10px;
          flex-wrap: wrap;
          margin-top: 18px;
        }}
        .btn {{
          appearance: none;
          border: none;
          border-radius: 10px;
          padding: 10px 14px;
          background: #fff;
          color: #0f172a;
          text-decoration: none;
          font-weight: 600;
          cursor: pointer;
        }}
        .btn.secondary {{
          background: rgba(255,255,255,.14);
          color: #fff;
          border: 1px solid rgba(255,255,255,.22);
        }}
        .grid {{
          display: grid;
          grid-template-columns: repeat(4, 1fr);
          gap: 14px;
          margin-top: 18px;
        }}
        .metric {{
          background: var(--panel);
          border: 1px solid var(--line);
          border-radius: 16px;
          padding: 18px;
          box-shadow: 0 8px 24px rgba(15, 23, 42, .05);
        }}
        .metric-label {{
          color: var(--muted);
          font-size: 12px;
          text-transform: uppercase;
          letter-spacing: .08em;
        }}
        .metric-value {{
          margin-top: 10px;
          font-size: 30px;
          font-weight: 700;
        }}
        .severity.critical .metric-value {{ color: var(--critical); }}
        .severity.high .metric-value {{ color: var(--high); }}
        .severity.medium .metric-value {{ color: var(--medium); }}
        .severity.low .metric-value {{ color: var(--low); }}
        .layout {{
          display: grid;
          grid-template-columns: 1.15fr .85fr;
          gap: 16px;
          margin-top: 18px;
        }}
        .panel {{
          background: var(--panel);
          border: 1px solid var(--line);
          border-radius: 18px;
          padding: 18px;
          box-shadow: 0 8px 24px rgba(15, 23, 42, .05);
        }}
        .panel h2 {{
          margin: 0 0 8px;
          font-size: 18px;
        }}
        .panel-note {{
          color: var(--muted);
          font-size: 13px;
          margin-bottom: 14px;
          line-height: 1.55;
        }}
        .flag-grid {{
          display: grid;
          grid-template-columns: repeat(2, 1fr);
          gap: 10px;
        }}
        .flag {{
          padding: 12px;
          border-radius: 12px;
          background: #f8fafc;
          border: 1px solid var(--line);
        }}
        .flag strong {{
          display: block;
          font-size: 22px;
          margin-top: 6px;
        }}
        table {{
          width: 100%;
          border-collapse: collapse;
        }}
        th, td {{
          text-align: left;
          padding: 10px 12px;
          border-bottom: 1px solid #e8edf5;
          font-size: 13px;
          vertical-align: top;
        }}
        th {{
          font-size: 12px;
          color: var(--muted);
          text-transform: uppercase;
          letter-spacing: .06em;
        }}
        .pill {{
          display: inline-flex;
          align-items: center;
          padding: 4px 8px;
          border-radius: 999px;
          font-size: 11px;
          font-weight: 700;
        }}
        .sev-critical {{ background: #fee2e2; color: #991b1b; }}
        .sev-high {{ background: #ffe4e6; color: #be123c; }}
        .sev-medium {{ background: #ffedd5; color: #9a3412; }}
        .sev-low {{ background: #ccfbf1; color: #115e59; }}
        ul {{
          margin: 0;
          padding-left: 18px;
        }}
        li {{
          margin: 8px 0;
          line-height: 1.55;
        }}
        .full {{
          margin-top: 16px;
        }}
        .muted {{
          color: var(--muted);
        }}
        @media (max-width: 980px) {{
          .grid {{ grid-template-columns: repeat(2, 1fr); }}
          .layout {{ grid-template-columns: 1fr; }}
          .flag-grid {{ grid-template-columns: 1fr; }}
        }}
        @media (max-width: 640px) {{
          .page {{ padding: 14px; }}
          .grid {{ grid-template-columns: 1fr; }}
          h1 {{ font-size: 28px; }}
          .hero {{ padding: 22px; }}
        }}
        @media print {{
          body {{ background: white; }}
          .page {{ max-width: none; padding: 0; }}
          .hero {{ box-shadow: none; }}
          .btn {{ display: none; }}
          .panel, .metric {{ box-shadow: none; }}
        }}
      </style>
    </head>
    <body>
      <div class="page">
        <section class="hero">
          <div class="eyebrow">Teacher logout session report</div>
          <h1>{escape(report.get('username', 'Teacher'))}'s monitoring summary</h1>
          <p>
            This report covers the exact monitoring window between dashboard login and logout,
            including alerts, machine activity, and the most important raw events captured in that period.
          </p>
          <div class="hero-meta">
            <span><strong>Login:</strong> {escape(_format_report_ts(report.get('login_time')))}</span>
            <span><strong>Logout:</strong> {escape(_format_report_ts(report.get('logout_time')))}</span>
            <span><strong>Duration:</strong> {escape(_format_duration(report.get('duration_seconds', 0)))}</span>
            <span><strong>Machines touched:</strong> {machine_count}</span>
          </div>
          <div class="actions">
            <button class="btn" onclick="window.print()">Print Report</button>
            <a class="btn secondary" href="/login">Return to Login</a>
          </div>
        </section>

        <section class="grid">
          <div class="metric">
            <div class="metric-label">Total Alerts</div>
            <div class="metric-value">{report.get('total_alerts', 0)}</div>
          </div>
          <div class="metric">
            <div class="metric-label">Total Events</div>
            <div class="metric-value">{report.get('total_logs', 0)}</div>
          </div>
          <div class="metric">
            <div class="metric-label">Screenshot Events</div>
            <div class="metric-value">{flag_counts.get('screenshot_events', 0)}</div>
          </div>
          <div class="metric">
            <div class="metric-label">USB Events</div>
            <div class="metric-value">{flag_counts.get('usb_events', 0)}</div>
          </div>
        </section>

        <section class="grid">
          {severity_cards}
        </section>

        <section class="layout">
          <div class="panel">
            <h2>Recommended Follow-up</h2>
            <div class="panel-note">
              Suggestions are generated from the alerts and events seen in this exact login-to-logout window.
            </div>
            <ul>{recommendations_html}</ul>
          </div>
          <div class="panel">
            <h2>Signal Snapshot</h2>
            <div class="panel-note">Quick counts for the most important event categories detected in this session.</div>
            <div class="flag-grid">
              <div class="flag">Suspicious window activity<strong>{flag_counts.get('suspicious_window_events', 0)}</strong></div>
              <div class="flag">Blocked browsing events<strong>{flag_counts.get('blocked_browser_events', 0)}</strong></div>
              <div class="flag">Terminal command events<strong>{flag_counts.get('terminal_events', 0)}</strong></div>
              <div class="flag">Source categories seen<strong>{len(activity_sources)}</strong></div>
            </div>
          </div>
        </section>

        <section class="layout">
          <div class="panel">
            <h2>Machine Activity</h2>
            <div class="panel-note">Machines are ranked by alert volume first, then total captured events.</div>
            <table>
              <thead>
                <tr>
                  <th>Hostname</th>
                  <th>Alerts</th>
                  <th>Events</th>
                </tr>
              </thead>
              <tbody>{machines_html}</tbody>
            </table>
          </div>
          <div class="panel">
            <h2>Activity Sources</h2>
            <div class="panel-note">Which monitor types were most active during this teacher session.</div>
            <table>
              <thead>
                <tr>
                  <th>Source</th>
                  <th>Events</th>
                </tr>
              </thead>
              <tbody>{sources_html}</tbody>
            </table>
          </div>
        </section>

        <section class="panel full">
          <h2>Alerts Raised During This Session</h2>
          <div class="panel-note">
            Showing the most recent {min(len(recent_alerts), 80)} alert entries captured between login and logout.
          </div>
          <table>
            <thead>
              <tr>
                <th>Severity</th>
                <th>Rule</th>
                <th>Hostname</th>
                <th>Detail</th>
                <th>Time</th>
              </tr>
            </thead>
            <tbody>{alerts_html}</tbody>
          </table>
        </section>

        <section class="panel full">
          <h2>Event Timeline</h2>
          <div class="panel-note">
            This merges raw event activity and alerts from the same session window, newest first.
          </div>
          <table>
            <thead>
              <tr>
                <th>Time</th>
                <th>Kind</th>
                <th>Level / Source</th>
                <th>Hostname</th>
                <th>Detail</th>
              </tr>
            </thead>
            <tbody>{timeline_html}</tbody>
          </table>
        </section>
      </div>
    </body>
    </html>
    """


@app.get("/login")
def login_page(request: Request):
    if _is_authenticated(request):
        return RedirectResponse(url="/", status_code=302)
    return HTMLResponse(_login_page())


@app.post("/login")
def do_login(request: Request, username: str = Form(...), password: str = Form(...)):
    username = username.strip()
    client_ip = _get_client_ip(request)
    rate_limit = get_teacher_login_rate_limit_status(
        username=username,
        remote_addr=client_ip,
        max_attempts=DASHBOARD_LOGIN_RATE_LIMIT_ATTEMPTS,
        window_seconds=DASHBOARD_LOGIN_RATE_LIMIT_WINDOW_SECONDS,
        lockout_seconds=DASHBOARD_LOGIN_RATE_LIMIT_LOCKOUT_SECONDS,
    )
    if rate_limit["blocked"]:
        record_teacher_login_attempt(username=username, remote_addr=client_ip, success=False)
        retry_after = _format_retry_after(rate_limit["retry_after_seconds"])
        return HTMLResponse(
            _login_page(f"Too many login attempts. Try again in {retry_after}."),
            status_code=429,
            headers={"Retry-After": str(rate_limit["retry_after_seconds"])},
        )

    authenticated_username = authenticate_teacher(username=username, password=password)
    if authenticated_username:
        login_session_id = secrets.token_hex(16)
        request.session["auth_ok"] = True
        request.session["teacher_username"] = authenticated_username["username"]
        request.session["teacher_role"] = authenticated_username["role"]
        request.session["teacher_allowed_hostnames"] = authenticated_username.get("allowed_hostnames", [])
        request.session["teacher_session_id"] = login_session_id
        create_teacher_login_session(session_id=login_session_id, username=authenticated_username["username"])
        record_teacher_login_attempt(username=authenticated_username["username"], remote_addr=client_ip, success=True)
        return RedirectResponse(url="/", status_code=302)
    record_teacher_login_attempt(username=username, remote_addr=client_ip, success=False)
    return HTMLResponse(_login_page("Invalid username or password"), status_code=401)


@app.get("/logout")
def logout(request: Request):
    login_session_id = request.session.get("teacher_session_id")
    current_user = _current_user(request)
    session_report = None
    if login_session_id:
        close_teacher_login_session(login_session_id)
        session_report = generate_session_report(
            login_session_id,
            viewer_username=current_user.get("username") if current_user else None,
            is_admin=bool(current_user and current_user.get("role") == "admin"),
            allowed_hostnames=_allowed_hostnames_for_user(current_user),
        )
    request.session.clear()
    if session_report and session_report.get("status") == "success":
        return HTMLResponse(_session_report_page(session_report))
    return RedirectResponse(url="/login", status_code=302)


@app.get("/api/sessions/last-report")
def api_get_last_session_report(request: Request):
    if not _is_authenticated(request):
        return {"status": "unauthorized"}
    login_session_id = request.session.get("teacher_session_id")
    current_user = _current_user(request)
    if not login_session_id:
        return {"status": "no_session"}
    return generate_session_report(
        login_session_id,
        viewer_username=current_user.get("username") if current_user else None,
        is_admin=bool(current_user and current_user.get("role") == "admin"),
        allowed_hostnames=_allowed_hostnames_for_user(current_user),
    )


@app.get("/")
def serve_dashboard(request: Request):
    if not _is_authenticated(request):
        return RedirectResponse(url="/login", status_code=302)
    with open(DASHBOARD_PATH, "r", encoding="utf-8") as f:
        return HTMLResponse(f.read())

@app.get("/api/agents")
def api_get_agents(request: Request):
    if not _is_authenticated(request):
        return HTMLResponse("Unauthorized", status_code=401)
    return get_all_agents(allowed_hostnames=_allowed_hostnames_for_user(_current_user(request)))


@app.post("/api/agents/{agent_id}/terminate-process")
async def api_terminate_agent_process(request: Request, agent_id: str):
    if not _is_authenticated(request):
        return HTMLResponse("Unauthorized", status_code=401)

    current_user = _current_user(request)
    agent = get_agent_by_id(agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found.")

    _ensure_hostname_allowed(current_user, agent.get("hostname"))

    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload.")

    process_name = str((payload or {}).get("process_name") or "").strip().lower()
    if process_name not in TERMINATE_PROCESS_TARGETS:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported process target. Allowed: {', '.join(sorted(TERMINATE_PROCESS_TARGETS))}",
        )
    pid = (payload or {}).get("pid")
    if pid is not None:
        try:
            pid = int(pid)
            if pid <= 0:
                raise ValueError
        except (TypeError, ValueError):
            raise HTTPException(status_code=400, detail="Invalid PID.")

    queued = queue_agent_command(
        agent_id=agent["agent_id"],
        hostname=agent["hostname"],
        requested_by=current_user.get("username") if current_user else "unknown",
        action="terminate_process",
        payload={"process_name": process_name, "pid": pid},
    )
    return {
        "status": "queued",
        "command_id": queued.get("id"),
        "agent_id": agent["agent_id"],
        "hostname": agent["hostname"],
        "process_name": process_name,
        "pid": pid,
        "message": (
            f"Stop request queued for PID {pid} ({process_name}) on {agent['hostname']}."
            if pid is not None
            else f"Stop request queued for {process_name} on {agent['hostname']}."
        ),
    }

@app.get("/api/alerts")
def api_get_alerts(request: Request, severity: str = None, limit: int = Query(500), date: str = None, hostname: str = None):
    if not _is_authenticated(request):
        return HTMLResponse("Unauthorized", status_code=401)
    current_user = _current_user(request)
    _ensure_hostname_allowed(current_user, hostname)
    return get_alerts(
        limit=limit,
        severity=severity,
        date_str=date,
        hostname=hostname,
        allowed_hostnames=_allowed_hostnames_for_user(current_user),
    )

@app.get("/api/alerts/stats")
def api_get_alert_stats(request: Request):
    if not _is_authenticated(request):
        return HTMLResponse("Unauthorized", status_code=401)
    return get_alert_counts(allowed_hostnames=_allowed_hostnames_for_user(_current_user(request)))

@app.post("/api/alerts/{alert_id}/acknowledge")
def api_ack_alert(request: Request, alert_id: int):
    if not _is_authenticated(request):
        return HTMLResponse("Unauthorized", status_code=401)
    updated = acknowledge_alert(alert_id, allowed_hostnames=_allowed_hostnames_for_user(_current_user(request)))
    if not updated:
        raise HTTPException(status_code=404, detail="Alert not found in your scope.")
    return {"status": "success"}

@app.get("/api/logs")
def api_get_logs(request: Request, limit: int = 100):
    if not _is_authenticated(request):
        return HTMLResponse("Unauthorized", status_code=401)
    return get_logs(limit=limit, allowed_hostnames=_allowed_hostnames_for_user(_current_user(request)))


@app.get("/api/auth/me")
def api_auth_me(request: Request):
    if not _is_authenticated(request):
        return HTMLResponse("Unauthorized", status_code=401)
    current_user = _current_user(request)
    return {
        "username": request.session.get("teacher_username"),
        "role": current_user.get("role") if current_user else "teacher",
        "allowed_hostnames": current_user.get("allowed_hostnames", []) if current_user else [],
        "scope_label": _scope_label(current_user),
    }


@app.get("/api/auth/access-log")
def api_teacher_access_log(request: Request, limit: int = Query(50)):
    if not _is_authenticated(request):
        return HTMLResponse("Unauthorized", status_code=401)
    current_user = _current_user(request)
    return get_recent_teacher_access(
        limit=limit,
        viewer_username=current_user.get("username") if current_user else None,
        is_admin=bool(current_user and current_user.get("role") == "admin"),
    )


@app.get("/api/insights/teacher")
def api_teacher_insights(request: Request, minutes: int = Query(60), hostname: str = None):
    if not _is_authenticated(request):
        return HTMLResponse("Unauthorized", status_code=401)
    current_user = _current_user(request)
    _ensure_hostname_allowed(current_user, hostname)
    return build_teacher_insights(
        minutes=minutes,
        hostname=hostname,
        allowed_hostnames=_allowed_hostnames_for_user(current_user),
    )


@app.get("/api/insights/teacher/stream")
async def api_teacher_insights_stream(request: Request, minutes: int = Query(60), hostname: str = None):
    if not _is_authenticated(request):
        return HTMLResponse("Unauthorized", status_code=401)
    current_user = _current_user(request)
    _ensure_hostname_allowed(current_user, hostname)

    async def event_generator():
        while True:
            if await request.is_disconnected():
                break
            payload = build_teacher_insights(
                minutes=minutes,
                hostname=hostname,
                allowed_hostnames=_allowed_hostnames_for_user(current_user),
            )
            yield f"data: {json.dumps(payload)}\n\n"
            await asyncio.sleep(3)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
        },
    )


@app.get("/api/insights/ask")
def api_teacher_ask(request: Request, question: str = Query(...), minutes: int = Query(60), hostname: str = None):
    if not _is_authenticated(request):
        return HTMLResponse("Unauthorized", status_code=401)
    current_user = _current_user(request)
    _ensure_hostname_allowed(current_user, hostname)
    return answer_teacher_query(
        question=question,
        minutes=minutes,
        hostname=hostname,
        allowed_hostnames=_allowed_hostnames_for_user(current_user),
    )


@app.get("/api/reports/class-period")
def api_class_period_report(request: Request, minutes: int = Query(60), hostname: str = None):
    if not _is_authenticated(request):
        return HTMLResponse("Unauthorized", status_code=401)
    current_user = _current_user(request)
    _ensure_hostname_allowed(current_user, hostname)
    html = build_class_period_report_html(
        minutes=minutes,
        hostname=hostname,
        allowed_hostnames=_allowed_hostnames_for_user(current_user),
    )
    return HTMLResponse(content=html)


@app.post("/api/maintenance/prune")
def api_prune_data(request: Request, log_days: int = Query(7), alert_days: int = Query(30)):
    if not _is_authenticated(request):
        return HTMLResponse("Unauthorized", status_code=401)
    _require_admin(_current_user(request))
    deleted = prune_old_data(log_days=log_days, alert_days=alert_days)
    return {
        "status": "success",
        "deleted": deleted,
        "policy": {
            "log_days": log_days,
            "alert_days": alert_days,
        },
    }

@app.post("/api/rules/reload")
def api_reload_rules(request: Request):
    if not _is_authenticated(request):
        return HTMLResponse("Unauthorized", status_code=401)
    _require_admin(_current_user(request))
    # In a full implementation, we'd signal the manager process.
    return {"status": "success", "message": "Reload signal sent (mocked)"}

if __name__ == "__main__":
    uvicorn.run("dashboard.api:app", host=API_HOST, port=API_PORT, reload=DASHBOARD_AUTO_RELOAD)
