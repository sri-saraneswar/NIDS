"""
=========================================================
Network Intrusion Detection System (NIDS)

Module : Console Manager (Refactored for Full-Stack)

Acts as a debug logger and state updater instead of a
presentation layer.
=========================================================
"""

import sys
import io
from datetime import datetime
from state.runtime_state import state_manager

# Configure stdout for UTF-8 on Windows
try:
    sys.stdout = io.TextIOWrapper(
        sys.stdout.buffer,
        encoding="utf-8",
        errors="replace",
        line_buffering=True,
        write_through=True
    )
except Exception:
    pass


def display_banner(interface="Unknown", version="3.0", author="Sri Saraneswar"):
    """Display the NIDS startup banner (Debug log)."""
    banner = f"""
  ================================================================
    _   _ _____ _____   _____
   | \ | |_   _|  __ \ / ____|
   |  \| | | | | |  | | (___
   | . ` | | | | |  | |\___ \\
   | |\  |_| |_| |__| |____) |
   |_| \_|_____|_____/|_____/

   Network Intrusion Detection System (Backend Services)
  ================================================================
  Version     : {version}
  Author      : {author}
  Interface   : {interface}
  Started     : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
  Web UI      : http://127.0.0.1:5000
  ================================================================
"""
    print(banner)


def display_live_status(stats):
    """No longer printing to console. State is handled centrally."""
    pass


def display_packet_log(packet, packet_number):
    """Debug log only."""
    pass


def display_alert(packet, attack):
    """Debug log only."""
    pass


def display_attack_progress(attack):
    """Debug log only."""
    pass


def display_finished_attack(attack):
    """Debug log only."""
    pass


def display_session_summary(summary):
    """Debug log only."""
    pass


def display_attack_history(attacks):
    """Debug log only."""
    pass


def display_db_status(msg):
    """Debug log only."""
    print(f"[DB] {msg}")

def display_session_status(msg):
    """Debug log only."""
    print(f"[SESSION] {msg}")
