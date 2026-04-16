import re
import sqlite3
import time
import html as html_lib
from collections import Counter
from datetime import datetime

from shared.config import DB_PATH


_DOMAIN_RE = re.compile(r"Domain=([^|\s]+)", re.IGNORECASE)
_COMMAND_RE = re.compile(r"Command=([^|]+)", re.IGNORECASE)

AI_DOMAIN_KEYWORDS = [
    "chatgpt", "openai", "gemini", "copilot", "claude", "perplexity", "poe.com",
]

GAME_DOMAIN_KEYWORDS = [
    "crazygames", "miniclip", "poki", "coolmathgames", "friv", "y8", "roblox", "steam",
]


def _priority_rank(priority: str) -> int:
    return {
        "Immediate review": 4,
        "Review soon": 3,
        "Monitor": 2,
        "Normal": 1,
    }.get(priority or "Normal", 1)


def _extract_domain(raw_log: str) -> str | None:
    if not raw_log:
        return None
    m = _DOMAIN_RE.search(raw_log)
    if m:
        value = m.group(1).strip().lower()
        value = value.strip('"\'()[]{}<>,;\\')
        return value
    return None


def _extract_command(raw_log: str) -> str | None:
    if not raw_log:
        return None
    m = _COMMAND_RE.search(raw_log)
    if m:
        return m.group(1).strip()
    return None


def _host_summary(hostname: str, since_ts: float) -> dict:
    conn = sqlite3.connect(DB_PATH)

    logs = conn.execute(
        """
        SELECT source, raw_log, timestamp
        FROM logs
        WHERE hostname = ? AND timestamp >= ?
        ORDER BY timestamp DESC
        """,
        (hostname, since_ts),
    ).fetchall()

    alerts = conn.execute(
        """
        SELECT severity, rule_name, matched_log, timestamp
        FROM alerts
        WHERE hostname = ? AND timestamp >= ? AND acknowledged = 0
        ORDER BY timestamp DESC
        """,
        (hostname, since_ts),
    ).fetchall()

    conn.close()

    source_counts = Counter(r[0] for r in logs)
    sev_counts = Counter(r[0] for r in alerts)

    domains = []
    commands = []
    timestamps = []
    for _, raw_log, ts in logs:
        timestamps.append(ts)
        domain = _extract_domain(raw_log)
        if domain:
            domains.append(domain)

        cmd = _extract_command(raw_log)
        if cmd:
            commands.append(cmd)

    domain_counts = Counter(domains)
    top_domains = [d for d, _ in domain_counts.most_common(5)]
    top_commands = [c for c, _ in Counter(commands).most_common(5)]

    ai_domains = sorted({d for d in domains if any(k in d for k in AI_DOMAIN_KEYWORDS)})
    game_domains = sorted({d for d in domains if any(k in d for k in GAME_DOMAIN_KEYWORDS)})

    flags = {
        "ai_usage": bool(ai_domains),
        "gaming": bool(game_domains),
        "screenshot": any("SCREENSHOT_TAKEN" in (r[1] or "") for r in logs),
        "usb": any("LAB_USB_INSERT" in (r[1] or "") for r in logs),
        "suspicious_window": any("SUSPICIOUS_WINDOW" in (r[1] or "") for r in logs),
        "blocked_browsing": any("BROWSER_BLOCKED" in (r[1] or "") for r in logs),
    }

    important_events = []
    seen_event_keys = set()
    for sev, rule_name, matched_log, ts in alerts:
        key = f"{sev}:{rule_name}:{matched_log[:120]}"
        if key in seen_event_keys:
            continue
        seen_event_keys.add(key)
        important_events.append(
            {
                "severity": sev,
                "rule_name": rule_name,
                "timestamp": ts,
                "detail": matched_log[:220],
            }
        )
        if len(important_events) >= 8:
            break

    critical = sev_counts.get("CRITICAL", 0)
    high = sev_counts.get("HIGH", 0)
    medium = sev_counts.get("MEDIUM", 0)
    low = sev_counts.get("LOW", 0)
    risk_score = (critical * 5) + (high * 3) + (medium * 1) + (low * 0.2)

    if critical > 0:
        priority = "Immediate review"
    elif high > 0:
        priority = "Review soon"
    elif medium > 0:
        priority = "Monitor"
    else:
        priority = "Normal"

    top_source = source_counts.most_common(1)[0][0] if source_counts else "None"
    session_start = min(timestamps) if timestamps else None
    session_end = max(timestamps) if timestamps else None

    recommendations = []
    if critical > 0:
        recommendations.append("Check this student immediately for exam-policy violation.")
    if high > 0:
        recommendations.append("Review high-severity events and speak to the student if repeated.")
    if flags["ai_usage"]:
        recommendations.append("Verify AI tool usage was allowed for this session.")
    if flags["gaming"]:
        recommendations.append("Confirm off-task gaming and keep this machine under closer watch.")
    if flags["usb"]:
        recommendations.append("Inspect USB file transfer risk and verify permitted device usage.")
    if flags["screenshot"]:
        recommendations.append("Check if screenshot capture violated assessment policy.")

    # keep concise
    recommendations = recommendations[:4]

    primary_risk_reason = "No major risk"
    if critical > 0:
        primary_risk_reason = f"{critical} critical alert(s)"
    elif high > 0:
        primary_risk_reason = f"{high} high alert(s)"
    elif flags["ai_usage"]:
        primary_risk_reason = "AI tool usage detected"
    elif flags["gaming"]:
        primary_risk_reason = "Gaming activity detected"

    brief = (
        f"{hostname}: {len(alerts)} alert(s) in window "
        f"(C:{critical}, H:{high}, M:{medium}, L:{low}). "
        f"Main activity={top_source}. Priority={priority}."
    )

    return {
        "hostname": hostname,
        "risk_score": round(risk_score, 2),
        "priority": priority,
        "brief": brief,
        "log_count": len(logs),
        "alert_count": len(alerts),
        "source_counts": dict(source_counts),
        "severity_counts": dict(sev_counts),
        "session_start": session_start,
        "session_end": session_end,
        "ai_usage_detected": bool(ai_domains),
        "gaming_detected": bool(game_domains),
        "ai_domains": ai_domains,
        "game_domains": game_domains,
        "domain_counts": dict(domain_counts),
        "flags": flags,
        "recommendations": recommendations,
        "primary_risk_reason": primary_risk_reason,
        "top_domains": top_domains,
        "top_commands": top_commands,
        "important_events": important_events,
    }


def build_teacher_insights(minutes: int = 60, hostname: str | None = None) -> dict:
    minutes = max(5, min(int(minutes), 1440))
    since_ts = time.time() - (minutes * 60)

    conn = sqlite3.connect(DB_PATH)
    if hostname:
        host_rows = conn.execute(
            "SELECT DISTINCT hostname FROM logs WHERE hostname = ?", (hostname,)
        ).fetchall()
    else:
        host_rows = conn.execute(
            """
            SELECT hostname, MAX(timestamp) AS last_ts
            FROM logs
            WHERE timestamp >= ?
            GROUP BY hostname
            ORDER BY last_ts DESC
            LIMIT 30
            """,
            (since_ts,),
        ).fetchall()
    conn.close()

    hostnames = [r[0] for r in host_rows] if host_rows else []

    hosts = [_host_summary(h, since_ts) for h in hostnames]
    hosts.sort(key=lambda x: x["risk_score"], reverse=True)

    total_alerts = sum(h["alert_count"] for h in hosts)
    total_logs = sum(h["log_count"] for h in hosts)

    class_overview = (
        f"Window={minutes} min | Machines analyzed={len(hosts)} | "
        f"Total alerts={total_alerts} | Total logs={total_logs}."
    )

    class_signals = {
        "ai_usage_machines": sum(1 for h in hosts if h.get("flags", {}).get("ai_usage")),
        "gaming_machines": sum(1 for h in hosts if h.get("flags", {}).get("gaming")),
        "screenshot_machines": sum(1 for h in hosts if h.get("flags", {}).get("screenshot")),
        "usb_machines": sum(1 for h in hosts if h.get("flags", {}).get("usb")),
        "blocked_browsing_machines": sum(1 for h in hosts if h.get("flags", {}).get("blocked_browsing")),
    }

    action_queue = [
        {
            "hostname": h["hostname"],
            "priority": h["priority"],
            "risk_score": h["risk_score"],
            "reason": h.get("primary_risk_reason", "No major risk"),
            "alert_count": h.get("alert_count", 0),
        }
        for h in hosts
        if h.get("alert_count", 0) > 0 or _priority_rank(h.get("priority")) >= 3
    ]
    action_queue.sort(key=lambda x: (_priority_rank(x["priority"]), x["risk_score"]), reverse=True)

    return {
        "generated_at": time.time(),
        "window_minutes": minutes,
        "class_overview": class_overview,
        "class_signals": class_signals,
        "action_queue": action_queue[:10],
        "hosts": hosts,
    }


def answer_teacher_query(question: str, minutes: int = 60, hostname: str | None = None) -> dict:
    """
    Local intent-based Q&A for teachers.
    Supported intents: summary, AI usage, gaming usage.
    """
    q = (question or "").strip().lower()
    insights = build_teacher_insights(minutes=minutes, hostname=hostname)
    hosts = insights.get("hosts", [])

    intent = "summary"
    if any(k in q for k in ["ai", "chatgpt", "copilot", "gemini", "llm"]):
        intent = "ai_usage"
    elif any(k in q for k in ["game", "gaming", "playing", "steam", "crazygames"]):
        intent = "gaming_usage"
    elif any(k in q for k in ["summary", "overall", "report", "session"]):
        intent = "summary"

    if intent == "ai_usage":
        matched = [
            {
                "hostname": h["hostname"],
                "ai_domains": h.get("ai_domains", []),
                "alert_count": h.get("alert_count", 0),
                "risk_score": h.get("risk_score", 0),
                "priority": h.get("priority", "Normal"),
            }
            for h in hosts
            if h.get("ai_usage_detected")
        ]
        if matched:
            answer = f"Yes. {len(matched)} machine(s) showed AI-related usage in the last {insights['window_minutes']} minutes."
        else:
            answer = f"No AI-related usage detected in the last {insights['window_minutes']} minutes."

    elif intent == "gaming_usage":
        matched = [
            {
                "hostname": h["hostname"],
                "game_domains": h.get("game_domains", []),
                "alert_count": h.get("alert_count", 0),
                "risk_score": h.get("risk_score", 0),
                "priority": h.get("priority", "Normal"),
            }
            for h in hosts
            if h.get("gaming_detected")
        ]
        if matched:
            answer = f"Yes. {len(matched)} machine(s) showed gaming-related usage in the last {insights['window_minutes']} minutes."
        else:
            answer = f"No gaming-related usage detected in the last {insights['window_minutes']} minutes."

    else:
        top = hosts[:3]
        matched = [
            {
                "hostname": h["hostname"],
                "priority": h.get("priority"),
                "alert_count": h.get("alert_count", 0),
                "risk_score": h.get("risk_score", 0),
                "severity_counts": h.get("severity_counts", {}),
                "top_domains": h.get("top_domains", [])[:3],
            }
            for h in top
        ]
        if matched:
            top_host = matched[0]
            sev = top_host.get("severity_counts", {})
            answer = (
                f"Summary ({insights.get('window_minutes')} min): "
                f"{insights.get('class_overview')} "
                f"Highest attention: {top_host['hostname']} "
                f"with {top_host['alert_count']} alert(s) "
                f"(C:{sev.get('CRITICAL',0)}, H:{sev.get('HIGH',0)}, "
                f"M:{sev.get('MEDIUM',0)}, L:{sev.get('LOW',0)})."
            )
        else:
            answer = insights.get("class_overview", "No summary available.")

    return {
        "question": question,
        "intent": intent,
        "window_minutes": insights.get("window_minutes"),
        "answer": answer,
        "matches": matched,
        "generated_at": time.time(),
    }


def _fmt_ts(ts: float | None) -> str:
        if not ts:
                return "—"
        return datetime.fromtimestamp(ts).strftime("%d %b %Y, %I:%M %p")


def _class_score(hosts: list[dict]) -> int:
        # Higher is better (0-100)
        penalty = 0
        for h in hosts:
                sev = h.get("severity_counts", {})
                penalty += sev.get("CRITICAL", 0) * 8
                penalty += sev.get("HIGH", 0) * 4
                penalty += sev.get("MEDIUM", 0) * 1
                penalty += sev.get("LOW", 0) * 0.25
        score = max(0, int(round(100 - penalty)))
        return min(score, 100)


def build_class_period_report_html(minutes: int = 60, hostname: str | None = None) -> str:
        insights = build_teacher_insights(minutes=minutes, hostname=hostname)
        hosts = insights.get("hosts", [])
        queue = insights.get("action_queue", [])
        signals = insights.get("class_signals", {})

        score = _class_score(hosts)
        risk_label = "Excellent" if score >= 90 else "Good" if score >= 75 else "Watch" if score >= 50 else "High Risk"
        now_txt = _fmt_ts(time.time())

        if queue:
                queue_html = "".join(
                        f"<li><strong>{html_lib.escape(item['hostname'])}</strong> — "
                        f"{html_lib.escape(item['priority'])} · "
                        f"{html_lib.escape(item['reason'])} "
                        f"(alerts: {item.get('alert_count', 0)})</li>"
                        for item in queue[:8]
                )
        else:
                queue_html = "<li>No immediate action items in this period.</li>"

        machine_cards = []
        for h in hosts[:12]:
                sev = h.get("severity_counts", {})
                top_sites = ", ".join(h.get("top_domains", [])[:3]) or "—"
                top_cmds = " | ".join(h.get("top_commands", [])[:2]) or "—"
                recos = h.get("recommendations", [])[:2]
                recos_html = "".join(f"<li>{html_lib.escape(r)}</li>" for r in recos) or "<li>No action required.</li>"
                machine_cards.append(
                        f"""
                        <div class=\"machine\">
                            <div class=\"machine-head\">
                                <h3>{html_lib.escape(h['hostname'])}</h3>
                                <span class=\"prio\">{html_lib.escape(h.get('priority','Normal'))}</span>
                            </div>
                            <div class=\"muted\">Session: {_fmt_ts(h.get('session_start'))} → {_fmt_ts(h.get('session_end'))}</div>
                            <div class=\"kv\">Alerts: <strong>{h.get('alert_count',0)}</strong> | Logs: <strong>{h.get('log_count',0)}</strong> | Risk score: <strong>{h.get('risk_score',0)}</strong></div>
                            <div class=\"kv\">C:{sev.get('CRITICAL',0)} H:{sev.get('HIGH',0)} M:{sev.get('MEDIUM',0)} L:{sev.get('LOW',0)}</div>
                            <div class=\"kv\">Top sites: {html_lib.escape(top_sites)}</div>
                            <div class=\"kv\">Top commands: {html_lib.escape(top_cmds)}</div>
                            <div class=\"kv\">Flags: AI={"Yes" if h.get('flags',{}).get('ai_usage') else "No"}, Games={"Yes" if h.get('flags',{}).get('gaming') else "No"}, Screenshot={"Yes" if h.get('flags',{}).get('screenshot') else "No"}</div>
                            <div class=\"section-title\">Recommended actions</div>
                            <ul>{recos_html}</ul>
                        </div>
                        """
                )

        machine_html = "".join(machine_cards) if machine_cards else "<p>No machine data for this period.</p>"

        return f"""
        <!doctype html>
        <html>
        <head>
            <meta charset=\"utf-8\" />
            <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\" />
            <title>Class Period Teacher Report</title>
            <style>
                body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Inter, Arial, sans-serif; margin: 0; background: #0f172a; color: #e2e8f0; }}
                .wrap {{ max-width: 1100px; margin: 0 auto; padding: 24px; }}
                .hero {{ background: linear-gradient(120deg,#1d4ed8,#0ea5e9); border-radius: 14px; padding: 20px 22px; color: #fff; }}
                .hero h1 {{ margin: 0 0 8px 0; font-size: 24px; }}
                .muted {{ color: #cbd5e1; font-size: 12px; margin-top: 4px; }}
                .grid {{ display: grid; grid-template-columns: repeat(4,1fr); gap: 10px; margin-top: 14px; }}
                .stat {{ background: #111827; border: 1px solid #334155; border-radius: 10px; padding: 12px; }}
                .stat .v {{ font-size: 24px; font-weight: 700; }}
                .panel {{ margin-top: 14px; background: #111827; border: 1px solid #334155; border-radius: 12px; padding: 14px; }}
                .panel h2 {{ margin: 0 0 10px; font-size: 16px; }}
                .machine-grid {{ display: grid; grid-template-columns: repeat(2,1fr); gap: 10px; }}
                .machine {{ background: #0b1220; border: 1px solid #334155; border-radius: 10px; padding: 12px; }}
                .machine-head {{ display: flex; justify-content: space-between; align-items: center; gap: 8px; }}
                .machine-head h3 {{ margin: 0; font-size: 15px; }}
                .prio {{ background: #1e293b; border: 1px solid #475569; border-radius: 999px; padding: 2px 8px; font-size: 11px; }}
                .kv {{ font-size: 12px; margin-top: 6px; color: #cbd5e1; }}
                .section-title {{ margin-top: 8px; font-size: 12px; color: #94a3b8; font-weight: 600; }}
                ul {{ margin: 8px 0 0 18px; padding: 0; }}
                li {{ margin: 4px 0; font-size: 12px; }}
                @media print {{ body {{ background: white; color: black; }} .hero {{ color: black; background: #e2e8f0; }} .panel,.stat,.machine {{ border-color: #cbd5e1; background: #fff; }} }}
            </style>
        </head>
        <body>
            <div class=\"wrap\">
                <div class=\"hero\">
                    <h1>Class Period Teacher Report Card</h1>
                    <div>{html_lib.escape(insights.get('class_overview','No overview'))}</div>
                    <div class=\"muted\">Generated: {html_lib.escape(now_txt)} | Window: {insights.get('window_minutes', minutes)} min</div>
                </div>

                <div class=\"grid\">
                    <div class=\"stat\"><div>Class Health Score</div><div class=\"v\">{score}</div><div class=\"muted\">{risk_label}</div></div>
                    <div class=\"stat\"><div>AI Usage Machines</div><div class=\"v\">{signals.get('ai_usage_machines',0)}</div></div>
                    <div class=\"stat\"><div>Gaming Machines</div><div class=\"v\">{signals.get('gaming_machines',0)}</div></div>
                    <div class=\"stat\"><div>Blocked Browsing</div><div class=\"v\">{signals.get('blocked_browsing_machines',0)}</div></div>
                </div>

                <div class=\"panel\">
                    <h2>Teacher Action Queue (Priority First)</h2>
                    <ul>{queue_html}</ul>
                </div>

                <div class=\"panel\">
                    <h2>Machine-by-Machine Summary</h2>
                    <div class=\"machine-grid\">{machine_html}</div>
                </div>
            </div>
        </body>
        </html>
        """
