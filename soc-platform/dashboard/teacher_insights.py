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


def _normalize_allowed_hostnames(allowed_hostnames: list[str] | None) -> list[str] | None:
    if allowed_hostnames is None:
        return None
    normalized = sorted({str(item).strip() for item in allowed_hostnames if str(item).strip()})
    if "*" in normalized:
        return None
    return normalized


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


def build_teacher_insights(
    minutes: int = 60,
    hostname: str | None = None,
    allowed_hostnames: list[str] | None = None,
) -> dict:
    minutes = max(5, min(int(minutes), 1440))
    since_ts = time.time() - (minutes * 60)
    normalized_allowed_hostnames = _normalize_allowed_hostnames(allowed_hostnames)

    conn = sqlite3.connect(DB_PATH)
    if hostname:
        query = "SELECT DISTINCT hostname FROM logs WHERE hostname = ?"
        params: list = [hostname]
        query, params = _append_hostname_scope(query, params, "hostname", normalized_allowed_hostnames)
        host_rows = conn.execute(query, tuple(params)).fetchall()
    else:
        query = """
            SELECT hostname, MAX(timestamp) AS last_ts
            FROM logs
            WHERE timestamp >= ?
        """
        params = [since_ts]
        query, params = _append_hostname_scope(query, params, "hostname", normalized_allowed_hostnames)
        query += """
            GROUP BY hostname
            ORDER BY last_ts DESC
            LIMIT 30
        """
        host_rows = conn.execute(query, tuple(params)).fetchall()
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


def answer_teacher_query(
    question: str,
    minutes: int = 60,
    hostname: str | None = None,
    allowed_hostnames: list[str] | None = None,
) -> dict:
    """
    Local intent-based Q&A for teachers.
    Supported intents: summary, AI usage, gaming usage.
    """
    q = (question or "").strip().lower()
    insights = build_teacher_insights(minutes=minutes, hostname=hostname, allowed_hostnames=allowed_hostnames)
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


def build_class_period_report_html(
        minutes: int = 60,
        hostname: str | None = None,
        allowed_hostnames: list[str] | None = None,
) -> str:
        insights = build_teacher_insights(minutes=minutes, hostname=hostname, allowed_hostnames=allowed_hostnames)
        hosts = insights.get("hosts", [])
        queue = insights.get("action_queue", [])
        signals = insights.get("class_signals", {})

        score = _class_score(hosts)
        risk_label = "Excellent" if score >= 90 else "Good" if score >= 75 else "Watch" if score >= 50 else "High Risk"
        grade = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D"
        now_txt = _fmt_ts(time.time())
        total_alerts = sum(int(h.get("alert_count", 0)) for h in hosts)
        total_logs = sum(int(h.get("log_count", 0)) for h in hosts)
        monitored_machines = len(hosts)
        high_priority_count = sum(1 for h in hosts if (h.get("priority") or "").upper() in {"HIGH", "CRITICAL"})

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
                :root {{
                    --bg: #f4f7fb;
                    --card: #ffffff;
                    --ink: #0f172a;
                    --muted: #475569;
                    --line: #dbe4f0;
                    --brand-1: #1d4ed8;
                    --brand-2: #0ea5e9;
                    --ok: #16a34a;
                    --warn: #d97706;
                    --risk: #dc2626;
                }}
                * {{ box-sizing: border-box; }}
                body {{
                    margin: 0;
                    background: linear-gradient(180deg, #eef3fb 0%, var(--bg) 100%);
                    color: var(--ink);
                    font-family: Inter, -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif;
                }}
                .wrap {{ max-width: 1180px; margin: 0 auto; padding: 28px 22px 34px; }}
                .report-shell {{ background: #f8fbff; border: 1px solid #d7e3f5; border-radius: 18px; padding: 18px; }}
                .hero {{
                    background: linear-gradient(135deg, var(--brand-1), var(--brand-2));
                    border-radius: 14px;
                    padding: 18px 20px;
                    color: #fff;
                    box-shadow: 0 10px 30px rgba(29, 78, 216, 0.24);
                }}
                .hero-top {{ display: flex; justify-content: space-between; align-items: flex-start; gap: 12px; }}
                .hero h1 {{ margin: 0 0 6px 0; font-size: 24px; letter-spacing: 0.2px; }}
                .subtitle {{ font-size: 13px; line-height: 1.45; color: #e8f2ff; max-width: 900px; }}
                .badge {{
                    background: rgba(255,255,255,0.18);
                    border: 1px solid rgba(255,255,255,0.35);
                    border-radius: 999px;
                    padding: 6px 11px;
                    font-size: 12px;
                    font-weight: 700;
                    white-space: nowrap;
                }}
                .meta {{ margin-top: 8px; font-size: 12px; color: #dbeafe; }}

                .kpis {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 10px; margin-top: 14px; }}
                .stat {{ background: var(--card); border: 1px solid var(--line); border-radius: 12px; padding: 12px; }}
                .stat .k {{ font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; color: #64748b; }}
                .stat .v {{ margin-top: 6px; font-size: 26px; font-weight: 800; line-height: 1; }}
                .stat .s {{ margin-top: 4px; font-size: 12px; color: var(--muted); }}

                .panel {{ margin-top: 12px; background: var(--card); border: 1px solid var(--line); border-radius: 12px; padding: 14px; }}
                .panel h2 {{ margin: 0 0 10px; font-size: 16px; }}
                .panel .lead {{ font-size: 12px; color: var(--muted); margin-bottom: 8px; }}

                .queue {{ margin: 0; padding-left: 18px; }}
                .queue li {{ margin: 6px 0; font-size: 13px; color: #1e293b; }}

                .machine-grid {{ display: grid; grid-template-columns: repeat(2, 1fr); gap: 10px; }}
                .machine {{ background: #ffffff; border: 1px solid var(--line); border-radius: 12px; padding: 12px; }}
                .machine-head {{ display: flex; justify-content: space-between; align-items: center; gap: 8px; }}
                .machine-head h3 {{ margin: 0; font-size: 15px; color: #0b1b36; }}
                .prio {{ background: #f1f5f9; border: 1px solid #cbd5e1; color: #334155; border-radius: 999px; padding: 3px 9px; font-size: 11px; font-weight: 700; }}
                .muted {{ font-size: 12px; color: var(--muted); margin-top: 5px; }}
                .kv {{ font-size: 12px; margin-top: 5px; color: #334155; line-height: 1.45; }}
                .section-title {{ margin-top: 9px; font-size: 12px; color: #1e3a8a; font-weight: 700; text-transform: uppercase; letter-spacing: 0.4px; }}
                .machine ul {{ margin: 7px 0 0 18px; padding: 0; }}
                .machine li {{ margin: 4px 0; font-size: 12px; color: #334155; }}

                .footer {{ margin-top: 12px; font-size: 11px; color: #64748b; text-align: right; }}

                @media (max-width: 980px) {{ .kpis {{ grid-template-columns: repeat(2, 1fr); }} .machine-grid {{ grid-template-columns: 1fr; }} }}
                @media print {{
                    body {{ background: #fff; }}
                    .wrap {{ padding: 0; max-width: none; }}
                    .report-shell {{ border: none; border-radius: 0; padding: 8px; }}
                    .hero {{ box-shadow: none; }}
                    .panel, .stat, .machine {{ break-inside: avoid; }}
                }}
            </style>
        </head>
        <body>
            <div class=\"wrap\">
                <div class=\"report-shell\">
                    <div class=\"hero\">
                        <div class=\"hero-top\">
                            <div>
                                <h1>Class Period Performance Report</h1>
                                <div class=\"subtitle\">{html_lib.escape(insights.get('class_overview', 'No overview'))}</div>
                            </div>
                            <div class=\"badge\">Grade {grade} · {risk_label}</div>
                        </div>
                        <div class=\"meta\">Generated: {html_lib.escape(now_txt)} · Monitoring window: {insights.get('window_minutes', minutes)} minutes</div>
                    </div>

                    <div class=\"kpis\">
                        <div class=\"stat\"><div class=\"k\">Class Health Score</div><div class=\"v\">{score}</div><div class=\"s\">{risk_label}</div></div>
                        <div class=\"stat\"><div class=\"k\">Monitored Machines</div><div class=\"v\">{monitored_machines}</div><div class=\"s\">Active in this period</div></div>
                        <div class=\"stat\"><div class=\"k\">Total Alerts</div><div class=\"v\">{total_alerts}</div><div class=\"s\">Across all devices</div></div>
                        <div class=\"stat\"><div class=\"k\">AI Usage Machines</div><div class=\"v\">{signals.get('ai_usage_machines',0)}</div><div class=\"s\">Potential AI-assisted activity</div></div>
                        <div class=\"stat\"><div class=\"k\">Gaming / High Priority</div><div class=\"v\">{signals.get('gaming_machines',0)} / {high_priority_count}</div><div class=\"s\">Gaming flags / priority devices</div></div>
                    </div>

                    <div class=\"panel\">
                        <h2>Teacher Action Queue</h2>
                        <div class=\"lead\">Priority-sorted recommendations for immediate classroom attention.</div>
                        <ul class=\"queue\">{queue_html}</ul>
                    </div>

                    <div class=\"panel\">
                        <h2>Machine-by-Machine Summary</h2>
                        <div class=\"lead\">Detailed behavior snapshot including alerts, activity signals, and suggested follow-up.</div>
                        <div class=\"machine-grid\">{machine_html}</div>
                    </div>

                    <div class=\"footer\">SOC Classroom Intelligence · Logs analyzed: {total_logs}</div>
                </div>
            </div>
        </body>
        </html>
        """
