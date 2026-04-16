import os
import sys
from contextlib import asynccontextmanager
from fastapi import FastAPI, Query, Request, Depends, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
import uvicorn

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
from database.db import init_db, get_all_agents, get_alerts, get_alert_counts, acknowledge_alert, get_logs
from database.db import prune_old_data
from shared.config import API_HOST, API_PORT, DASHBOARD_PASSWORD, DASHBOARD_SESSION_SECRET
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


def _is_authenticated(request: Request) -> bool:
    return bool(request.session.get("auth_ok"))


def require_auth(request: Request):
    if not _is_authenticated(request):
        raise PermissionError("Unauthorized")


def _login_page(error: str = "") -> str:
    error_html = f"<div style='color:#ef4444;margin-bottom:10px'>{error}</div>" if error else ""
    return f"""
    <!doctype html>
    <html>
    <head>
      <meta charset=\"utf-8\" />
      <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\" />
      <title>Lab Monitor Login</title>
      <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif; margin:0; background:#0f172a; color:#e2e8f0; }}
        .wrap {{ min-height:100vh; display:flex; align-items:center; justify-content:center; padding:16px; }}
        .card {{ width:360px; background:#111827; border:1px solid #334155; border-radius:12px; padding:18px; }}
        h2 {{ margin:0 0 12px; font-size:20px; }}
        .muted {{ color:#94a3b8; font-size:13px; margin-bottom:12px; }}
        input {{ width:100%; box-sizing:border-box; background:#0b1220; color:#e2e8f0; border:1px solid #334155; border-radius:8px; padding:10px; margin-bottom:10px; }}
        button {{ width:100%; background:#2563eb; color:#fff; border:none; border-radius:8px; padding:10px; font-weight:600; cursor:pointer; }}
      </style>
    </head>
    <body>
      <div class=\"wrap\">
        <div class=\"card\">
          <h2>🔐 Lab Monitor Login</h2>
          <div class=\"muted\">Authorized staff access only</div>
          {error_html}
          <form method=\"post\" action=\"/login\">
            <input type=\"password\" name=\"password\" placeholder=\"Enter password\" required />
            <button type=\"submit\">Sign In</button>
          </form>
        </div>
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
def do_login(request: Request, password: str = Form(...)):
    if password == DASHBOARD_PASSWORD:
        request.session["auth_ok"] = True
        return RedirectResponse(url="/", status_code=302)
    return HTMLResponse(_login_page("Invalid password"), status_code=401)


@app.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/login", status_code=302)


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
    return get_all_agents()

@app.get("/api/alerts")
def api_get_alerts(request: Request, severity: str = None, limit: int = Query(500), date: str = None):
    if not _is_authenticated(request):
        return HTMLResponse("Unauthorized", status_code=401)
    return get_alerts(limit=limit, severity=severity, date_str=date)

@app.get("/api/alerts/stats")
def api_get_alert_stats(request: Request):
    if not _is_authenticated(request):
        return HTMLResponse("Unauthorized", status_code=401)
    return get_alert_counts()

@app.post("/api/alerts/{alert_id}/acknowledge")
def api_ack_alert(request: Request, alert_id: int):
    if not _is_authenticated(request):
        return HTMLResponse("Unauthorized", status_code=401)
    acknowledge_alert(alert_id)
    return {"status": "success"}

@app.get("/api/logs")
def api_get_logs(request: Request, limit: int = 100):
    if not _is_authenticated(request):
        return HTMLResponse("Unauthorized", status_code=401)
    return get_logs(limit=limit)


@app.get("/api/insights/teacher")
def api_teacher_insights(request: Request, minutes: int = Query(60), hostname: str = None):
    if not _is_authenticated(request):
        return HTMLResponse("Unauthorized", status_code=401)
    return build_teacher_insights(minutes=minutes, hostname=hostname)


@app.get("/api/insights/ask")
def api_teacher_ask(request: Request, question: str = Query(...), minutes: int = Query(60), hostname: str = None):
    if not _is_authenticated(request):
        return HTMLResponse("Unauthorized", status_code=401)
    return answer_teacher_query(question=question, minutes=minutes, hostname=hostname)


@app.get("/api/reports/class-period")
def api_class_period_report(request: Request, minutes: int = Query(60), hostname: str = None):
    if not _is_authenticated(request):
        return HTMLResponse("Unauthorized", status_code=401)
    html = build_class_period_report_html(minutes=minutes, hostname=hostname)
    return HTMLResponse(content=html)


@app.post("/api/maintenance/prune")
def api_prune_data(request: Request, log_days: int = Query(7), alert_days: int = Query(30)):
    if not _is_authenticated(request):
        return HTMLResponse("Unauthorized", status_code=401)
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
    # In a full implementation, we'd signal the manager process.
    return {"status": "success", "message": "Reload signal sent (mocked)"}

if __name__ == "__main__":
    uvicorn.run(app, host=API_HOST, port=API_PORT, reload=False)
