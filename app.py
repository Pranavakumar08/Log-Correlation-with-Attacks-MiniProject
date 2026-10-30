# Main Flask Web Application & REST API
# Insider Threat Detection SIEM Dashboard and Simulation Controller

import threading
import time
from datetime import datetime
from flask import Flask, render_template, jsonify, request, Response
from correlation_engine import CorrelationEngine
from log_generator import LogGenerator, USER_PERSONAS
from models import LogSource, LogEvent

app = Flask(__name__)

# Core singleton instances
engine = CorrelationEngine(time_window_minutes=60)
generator = LogGenerator()

# Simulation state
simulation_lock = threading.Lock()
sim_state = {
    "is_running": False,
    "speed": 1.0,           # 1.0 = 1 log every 2 sec, 2.0 = 1 log/sec, 5.0 = 2.5 logs/sec
    "threat_rate": 0.15,     # 15% random anomaly rate
    "total_cycles": 0,
    "current_scenario": "None"
}

def simulation_worker():
    """Background worker that pushes simulated logs into the correlation engine."""
    while True:
        with simulation_lock:
            running = sim_state["is_running"]
            speed = sim_state["speed"]
            threat_rate = sim_state["threat_rate"]

        if running:
            # Generate a normal or anomalous log event
            if random_threat_trigger(threat_rate):
                # Small anomalous micro-event
                anom_type = sim_state.get("next_anom", None)
                if not anom_type:
                    # Pick a persona to do something slightly unusual
                    ev = generator.generate_random_normal_log()
                    # Occasionally mutate to test correlation
                    if ev.source == LogSource.FILE_ACCESS and ev.user_id == "marcus.vance":
                        ev.details["sensitivity"] = "CONFIDENTIAL"
                        ev.action = "FILE_DOWNLOAD"
                else:
                    ev = generator.generate_random_normal_log()
            else:
                ev = generator.generate_random_normal_log()

            with simulation_lock:
                engine.process_event(ev)
                sim_state["total_cycles"] += 1

            # Sleep inversely proportional to speed
            sleep_time = max(0.2, 2.0 / speed)
            time.sleep(sleep_time)
        else:
            time.sleep(0.5)

def random_threat_trigger(rate: float) -> bool:
    import random
    return random.random() < rate

# Start simulation daemon thread
sim_thread = threading.Thread(target=simulation_worker, daemon=True)
sim_thread.start()

# --- Web Routes ---

@app.route("/")
def index():
    """Serves the main SIEM monitoring and simulation dashboard."""
    return render_template("index.html")

# --- REST API Endpoints ---

@app.route("/api/status", methods=["GET"])
def get_status():
    """Returns engine state, simulation config, and summary counters."""
    with simulation_lock:
        return jsonify({
            "is_running": sim_state["is_running"],
            "speed": sim_state["speed"],
            "total_cycles": sim_state["total_cycles"],
            "current_scenario": sim_state["current_scenario"],
            "analytics": engine.get_analytics()
        })

@app.route("/api/simulation/start", methods=["POST"])
def start_simulation():
    """Starts / resumes the continuous background log stream."""
    with simulation_lock:
        sim_state["is_running"] = True
        sim_state["current_scenario"] = "Continuous Ingestion Stream"
    return jsonify({"success": True, "message": "Simulation started", "is_running": True})

@app.route("/api/simulation/pause", methods=["POST"])
def pause_simulation():
    """Pauses the background log stream."""
    with simulation_lock:
        sim_state["is_running"] = False
    return jsonify({"success": True, "message": "Simulation paused", "is_running": False})

@app.route("/api/simulation/reset", methods=["POST"])
def reset_simulation():
    """Resets all collected logs, incidents, and counters."""
    with simulation_lock:
        sim_state["is_running"] = False
        sim_state["total_cycles"] = 0
        sim_state["current_scenario"] = "None"
        engine.reset()
    return jsonify({"success": True, "message": "Simulation and correlation buffer reset"})

@app.route("/api/simulation/speed", methods=["POST"])
def set_speed():
    """Adjusts the simulation speed multiplier."""
    data = request.get_json() or {}
    speed = float(data.get("speed", 1.0))
    if speed in [1.0, 2.0, 5.0, 10.0]:
        with simulation_lock:
            sim_state["speed"] = speed
        return jsonify({"success": True, "speed": speed})
    return jsonify({"error": "Invalid speed multiplier"}), 400

@app.route("/api/simulation/trigger-scenario", methods=["POST"])
def trigger_scenario():
    """Triggers an end-to-end multi-source insider threat scenario."""
    data = request.get_json() or {}
    scenario_name = data.get("scenario")
    
    events = []
    desc = ""
    
    if scenario_name == "exfiltration":
        events = generator.generate_scenario_departing_exfiltrator()
        desc = "The Departing Exfiltrator (Resignation + Off-Hours VPN + DB Dump + USB Export)"
    elif scenario_name == "rogue_admin":
        events = generator.generate_scenario_rogue_admin_tamper()
        desc = "Rogue Admin Sabotage (SSH + Root Privilege + Disabling Audit Logs)"
    elif scenario_name == "impossible_travel":
        events = generator.generate_scenario_impossible_travel()
        desc = "Impossible Travel & Account Takeover (NYC Login -> 15m Frankfurt VPN -> DB Dump)"
    elif scenario_name == "snooping":
        events = generator.generate_scenario_cross_snooping()
        desc = "Cross-Department Asset Snooping (Accessing Patents & Confidential M&A TermSheet)"
    elif scenario_name == "normal_batch":
        events = [generator.generate_random_normal_log() for _ in range(8)]
        desc = "Standard Enterprise Baseline Traffic Batch (8 Benign Logs)"
    else:
        return jsonify({"error": f"Unknown scenario: {scenario_name}"}), 400

    new_incidents = []
    with simulation_lock:
        sim_state["current_scenario"] = desc
        for ev in events:
            incs = engine.process_event(ev)
            new_incidents.extend(incs)

    return jsonify({
        "success": True,
        "scenario": desc,
        "events_injected": len(events),
        "incidents_triggered": len(new_incidents),
        "incidents": [i.to_dict() for i in new_incidents]
    })

@app.route("/api/simulation/inject-log", methods=["POST"])
def inject_custom_log():
    """Allows manual injection of a custom crafted log event."""
    data = request.get_json() or {}
    user_id = data.get("user_id")
    source_str = data.get("source")
    action = data.get("action", "CUSTOM_ACTION")
    details = data.get("details", {})

    if not user_id or not source_str:
        return jsonify({"error": "user_id and source are required"}), 400

    # Match persona metadata
    persona = generator.personas.get(user_id, {
        "user_id": user_id,
        "user_name": user_id.replace(".", " ").title(),
        "department": data.get("department", "Engineering"),
        "location": "HQ",
        "ip_home": "10.0.0.1"
    })

    # Match source
    try:
        source_enum = LogSource(source_str)
    except ValueError:
        # Fallback to source string or nearest match
        source_enum = LogSource.AUTH

    ev = LogEvent(
        source=source_enum,
        user_id=persona["user_id"],
        user_name=persona["user_name"],
        department=persona["department"],
        action=action,
        details=details,
        timestamp=datetime.now(),
        is_synthetic_threat=data.get("is_threat", False)
    )

    with simulation_lock:
        new_incidents = engine.process_event(ev)

    return jsonify({
        "success": True,
        "event": ev.to_dict(),
        "triggered_incident": len(new_incidents) > 0,
        "new_incidents": [i.to_dict() for i in new_incidents]
    })

@app.route("/api/logs", methods=["GET"])
def get_logs():
    """Fetches the latest ingested raw log events."""
    limit = int(request.args.get("limit", 60))
    source = request.args.get("source")
    user = request.args.get("user")
    logs = engine.get_logs(limit=limit, source_filter=source, user_filter=user)
    return jsonify({"count": len(logs), "logs": logs})

@app.route("/api/incidents", methods=["GET"])
def get_incidents():
    """Fetches correlated threat incidents."""
    severity = request.args.get("severity")
    incidents = engine.get_incidents(severity_filter=severity)
    return jsonify({"count": len(incidents), "incidents": incidents})

@app.route("/api/incidents/<incident_id>", methods=["GET"])
def get_incident_details(incident_id):
    """Retrieves forensic details for a single incident."""
    incident = engine.get_incident_by_id(incident_id)
    if not incident:
        return jsonify({"error": "Incident not found"}), 404
    return jsonify(incident)

@app.route("/api/incidents/<incident_id>/status", methods=["POST"])
def update_incident_status(incident_id):
    """Updates incident containment / resolution state."""
    data = request.get_json() or {}
    new_status = data.get("status")
    if new_status in ["OPEN", "INVESTIGATING", "CONTAINED", "RESOLVED", "FALSE_POSITIVE"]:
        updated = engine.update_incident_status(incident_id, new_status)
        if updated:
            return jsonify({"success": True, "incident_id": incident_id, "status": new_status})
    return jsonify({"error": "Invalid status or incident ID"}), 400

@app.route("/api/users", methods=["GET"])
def get_users_risk():
    """Returns the user risk profile leaderboard."""
    return jsonify({
        "users": engine.get_risk_leaderboard(),
        "personas": USER_PERSONAS
    })

@app.route("/api/rules", methods=["GET"])
def get_rules():
    """Returns the registered correlation rules and MITRE ATT&CK techniques."""
    rules = [r.to_dict() for r in engine.rules.values()]
    return jsonify({"rules": rules})

@app.route("/api/export-report", methods=["GET"])
def export_report():
    """
    Generates a full forensic text/markdown summary report suitable for
    academic project submission, lab documentation, or viva evaluation.
    """
    analytics = engine.get_analytics()
    incidents = engine.get_incidents()
    users = engine.get_risk_leaderboard()

    timestamp_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    report_lines = [
        "=" * 80,
        "INSIDER THREAT DETECTION VIA LOG CORRELATION - FORENSIC INCIDENT REPORT",
        "System Information and Management - Cyber Security Honours MiniProject",
        f"Generated: {timestamp_str}",
        "=" * 80,
        "",
        "1. EXECUTIVE SUMMARY & THREAT POSTURE",
        f"  - Overall Threat Posture: {analytics['threat_level']}",
        f"  - Total Ingested Logs:    {analytics['total_logs']}",
        f"  - Total Incidents Flagged:{analytics['total_incidents']}",
        f"  - Correlated Anomalies:   {analytics['anomalies_detected']}",
        f"  - Monitored Identities:   {analytics['active_users_tracked']}",
        f"  - High-Risk Insiders:     {analytics['high_risk_users_count']}",
        "",
        "2. SEVERITY BREAKDOWN",
        f"  - CRITICAL: {analytics['severity_breakdown']['CRITICAL']}",
        f"  - HIGH:     {analytics['severity_breakdown']['HIGH']}",
        f"  - MEDIUM:   {analytics['severity_breakdown']['MEDIUM']}",
        f"  - LOW:      {analytics['severity_breakdown']['LOW']}",
        "",
        "3. LOG INGESTION SOURCE DISTRIBUTION",
    ]
    
    for src, count in analytics["source_breakdown"].items():
        report_lines.append(f"  - {src:20}: {count} events")
        
    report_lines.extend([
        "",
        "4. TOP SUSPICIOUS INSIDERS (RISK LEADERBOARD)",
        "-" * 80,
        f"{'User ID':18} | {'User Name':18} | {'Department':15} | {'Risk Score':10} | {'Status':14}"
    ])
    
    for u in users[:10]:
        report_lines.append(f"{u['user_id']:18} | {u['user_name']:18} | {u['department']:15} | {u['risk_score']:3}/100    | {u['status']:14}")

    report_lines.extend([
        "",
        "5. DETECTED CORRELATION INCIDENTS & EVIDENCE TIMELINES",
        "-" * 80
    ])

    if not incidents:
        report_lines.append("  No security incidents detected or simulation not yet run.")
    else:
        for idx, inc in enumerate(incidents, 1):
            report_lines.extend([
                f"\n[INCIDENT #{idx}] ID: {inc['incident_id']} - {inc['title']}",
                f"  Severity:       {inc['severity']} (Composite Risk Score: {inc['risk_score']}/100)",
                f"  User:           {inc['user_name']} ({inc['user_id']}) - Dept: {inc['department']}",
                f"  Matched Rule:   [{inc['rule_id']}] {inc['rule_name']}",
                f"  MITRE ATT&CK:   {inc['mitre_technique']}",
                f"  Detection Time: {inc['detected_at']}",
                f"  Current Status: {inc['status']}",
                f"  Summary:        {inc['summary']}",
                "  Correlation Chain (Evidence Trail):"
            ])
            for e_idx, ev in enumerate(inc["correlated_events"], 1):
                report_lines.append(f"    [{e_idx}] {ev['timestamp']} | {ev['source']:16} | Action: {ev['action']:18} | Details: {ev['details']}")
            report_lines.append("  Containment & Remediation Recommendations:")
            for rec in inc["recommendations"]:
                report_lines.append(f"    * {rec}")

    report_lines.extend([
        "",
        "=" * 80,
        "END OF FORENSIC INCIDENT REPORT - LOG CORRELATION SIEM",
        "=" * 80
    ])

    full_report_text = "\n".join(report_lines)
    return Response(full_report_text, mimetype="text/plain", headers={"Content-Disposition": "attachment;filename=insider_threat_report.txt"})

if __name__ == "__main__":
    print("=" * 60)
    print("  Insider Threat Detection SIEM - Log Correlation Engine")
    print("  System Information & Management MiniProject")
    print("  Server running at: http://127.0.0.1:5000")
    print("=" * 60)
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
