"""
====================================================
Network Intrusion Detection System (NIDS)

Module : Dashboard Routes

Defines the web UI and API endpoints.
====================================================
"""

from flask import render_template, jsonify, request
from dashboard import app
from detection.statistics import get_statistics, get_top_hosts
from session.session_manager import get_attack_summary, get_current_session

# --- Web Pages ---

@app.route('/')
def index():
    """Render the main dashboard UI."""
    return render_template('index.html')

@app.route('/live')
def live():
    """Render the live monitor page."""
    return render_template('live.html')

@app.route('/alerts')
def alerts():
    """Render the alerts page."""
    return render_template('alerts.html')

@app.route('/analytics')
def analytics():
    """Render the analytics page."""
    return render_template('analytics.html')

@app.route('/history')
def history():
    """Render the attack history page."""
    return render_template('history.html')

@app.route('/reports')
def reports():
    """Render the reports page."""
    return render_template('reports.html')

@app.route('/settings')
def settings():
    """Render the settings page."""
    return render_template('settings.html')


# --- APIs (Backend Communication Layer) ---

from state.runtime_state import state_manager

@app.route('/api/dashboard')
def api_dashboard():
    """Return the centralized dashboard state."""
    return jsonify(state_manager.get_dashboard_state())

@app.route('/api/live')
def api_live():
    """Return the recent live packets."""
    return jsonify(state_manager.get_live_packets())

@app.route('/api/alerts')
def api_alerts():
    """Return current active alerts/attacks."""
    return jsonify(state_manager.get_active_attacks())

@app.route('/api/history')
def api_history():
    """Return historical finished attacks."""
    return jsonify(state_manager.get_attack_history())

@app.route('/api/hosts')
def api_hosts():
    """Return top communicating hosts."""
    return jsonify(state_manager.get_top_hosts(10))

@app.route('/api/statistics')
def api_statistics():
    """Return raw statistics."""
    return jsonify(state_manager.get_statistics())


# --- Control APIs ---
import threading
from scapy.all import get_if_list
from capture.capture import start_capture, stop_capture
from session.session_manager import start_session, stop_session
from alert.alert import AlertManager
from analyzer.analyzer import set_alert_manager, set_monitor_mode

_alert_manager_instance = None
_capture_thread = None

@app.route('/api/interfaces')
def api_interfaces():
    """Return list of available network interfaces."""
    return jsonify(get_if_list())

@app.route('/api/is_monitoring')
def api_is_monitoring():
    """Return the global monitoring state."""
    return jsonify({
        "is_monitoring": state_manager.is_monitoring,
        "interface": state_manager.current_interface
    })

@app.route('/api/start', methods=['POST'])
def api_start():
    """Start the NIDS engines."""
    global _alert_manager_instance, _capture_thread
    
    if state_manager.is_monitoring:
        return jsonify({"status": "Already Running", "interface": state_manager.current_interface})
    
    data = request.json or {}
    interface = data.get('interface', 'ALL')
    
    state_manager.set_monitoring(True, interface)
    
    # 1. Start Session
    start_session(interface=interface)
    
    # 2. Start Alert System
    if not _alert_manager_instance:
        _alert_manager_instance = AlertManager()
        _alert_manager_instance.start()
        set_alert_manager(_alert_manager_instance)
        
    # 3. Setup Capture Mode
    # ALWAYS set to ALL so that analyzer passes all packets to console_manager (which now saves them to state)
    set_monitor_mode("ALL")
        
    # 4. Start Capture in background thread so it doesn't block Flask
    if not _capture_thread or not _capture_thread.is_alive():
        _capture_thread = threading.Thread(
            target=start_capture, 
            args=(interface,),
            daemon=True
        )
        _capture_thread.start()
        
    return jsonify({"status": "started", "interface": interface})

@app.route('/api/stop', methods=['POST'])
def api_stop():
    """Stop the NIDS engines."""
    global _alert_manager_instance, _capture_thread
    
    if not state_manager.is_monitoring:
        return jsonify({"status": "Already Stopped"})
    
    stop_capture()
    
    if _capture_thread and _capture_thread.is_alive():
        _capture_thread.join(timeout=2.0)
    
    if _alert_manager_instance:
        _alert_manager_instance.stop()
        _alert_manager_instance = None
        
    stop_session()
    
    state_manager.set_monitoring(False, None)
    
    return jsonify({"status": "stopped"})

