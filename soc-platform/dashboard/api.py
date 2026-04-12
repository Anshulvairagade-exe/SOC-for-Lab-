import os
import sys
from contextlib import asynccontextmanager
from fastapi import FastAPI, Query
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
from database.db import init_db, get_all_agents, get_alerts, get_alert_counts, acknowledge_alert, get_logs
from shared.config import API_HOST, API_PORT

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield

app = FastAPI(title="SOC Platform API", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DASHBOARD_PATH = os.path.join(os.path.dirname(__file__), "templates", "index.html")

@app.get("/")
def serve_dashboard():
    with open(DASHBOARD_PATH, "r", encoding="utf-8") as f:
        return HTMLResponse(f.read())

@app.get("/api/agents")
def api_get_agents():
    return get_all_agents()

@app.get("/api/alerts")
def api_get_alerts(severity: str = None, limit: int = Query(500), date: str = None):
    return get_alerts(limit=limit, severity=severity, date_str=date)

@app.get("/api/alerts/stats")
def api_get_alert_stats():
    return get_alert_counts()

@app.post("/api/alerts/{alert_id}/acknowledge")
def api_ack_alert(alert_id: int):
    acknowledge_alert(alert_id)
    return {"status": "success"}

@app.get("/api/logs")
def api_get_logs(limit: int = 100):
    return get_logs(limit=limit)

@app.post("/api/rules/reload")
def api_reload_rules():
    # In a full implementation, we'd signal the manager process.
    return {"status": "success", "message": "Reload signal sent (mocked)"}

if __name__ == "__main__":
    uvicorn.run(app, host=API_HOST, port=API_PORT, reload=False)
