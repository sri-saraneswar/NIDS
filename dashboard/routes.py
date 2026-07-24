"""
====================================================
Network Intrusion Detection System (NIDS)

Module : Dashboard Routes

Defines the web UI and API endpoints.
====================================================
"""

from flask import render_template, jsonify
from dashboard import app
from detection.statistics import get_statistics, get_top_hosts
from session.session_manager import get_attack_summary, get_current_session

@app.route('/')
def index():
    """Render the main dashboard UI."""
    return render_template('index.html')

@app.route('/api/status')
def api_status():
    """Return live system statistics."""
    stats = get_statistics()
    return jsonify({
        "packets": stats.get("packets", 0),
        "total_bytes": stats.get("total_bytes", 0),
        "alerts": stats.get("alerts", 0),
        "warnings": stats.get("warnings", 0),
        "risk": stats.get("risk", "LOW"),
        "risk_stats": {
            "CRITICAL": stats.get("critical", 0),
            "HIGH": stats.get("high", 0),
            "MEDIUM": stats.get("medium", 0),
            "LOW": stats.get("low", 0)
        },
        "protocol_counts": stats.get("protocol_counts", {})
    })

@app.route('/api/attacks')
def api_attacks():
    """Return current and historical attacks."""
    session = get_current_session()
    
    active_attacks = []
    if session:
        active_attacks = list(session.active_attacks.values())
        
    history = get_attack_summary()
    
    return jsonify({
        "active": active_attacks,
        "history": history
    })

@app.route('/api/hosts')
def api_hosts():
    """Return top communicating hosts."""
    hosts = get_top_hosts(10)
    # Convert list of tuples to list of dicts for JSON
    hosts_list = [{"ip": h[0], "packets": h[1]} for h in hosts]
    return jsonify(hosts_list)
