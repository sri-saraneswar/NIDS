"""
====================================================
Network Intrusion Detection System (NIDS)
Module : Session
Description:
Represents one IDS monitoring session.
====================================================
"""

from datetime import datetime


class Session:
    """
    Represents one monitoring session.
    """

    def __init__(self, session_id):

        self.session_id = session_id

        self.start_time = datetime.now()

        self.end_time = None

        self.status = "ACTIVE"

        # ----------------------------
        # Runtime Statistics
        # ----------------------------

        self.total_packets = 0

        self.total_flows = 0

        self.active_flows = 0

        self.completed_flows = 0

        self.total_alerts = 0

        self.risk = "LOW"

    # ==========================================
    # Packet Counter
    # ==========================================

    def add_packet(self):

        self.total_packets += 1

    # ==========================================
    # Flow Counter
    # ==========================================

    def update_flows(self,
                     total,
                     active,
                     completed):

        self.total_flows = total

        self.active_flows = active

        self.completed_flows = completed

    # ==========================================
    # Alert Counter
    # ==========================================

    def add_alert(self):

        self.total_alerts += 1

    # ==========================================
    # Risk Level
    # ==========================================
    def update_risk(self, risk):

     levels = {
        "INFO": 0,
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
        "CRITICAL": 4
    }

    if risk in levels and levels[risk] > levels[self.risk]:
        self.risk = risk

    # ==========================================
    # Close Session
    # ==========================================

    def close(self):

        self.end_time = datetime.now()

        self.status = "COMPLETED"

    # ==========================================
    # Session Duration
    # ==========================================

    @property
    def duration(self):

        end = self.end_time or datetime.now()

        return (end - self.start_time).total_seconds()

    # ==========================================
    # Convert to Dictionary
    # ==========================================

    def to_dict(self):

        return {

            "session_id": self.session_id,

            "start_time": self.start_time,

            "end_time": self.end_time,

            "duration": self.duration,

            "status": self.status,

            "packets": self.total_packets,

            "flows": self.total_flows,

            "active_flows": self.active_flows,

            "completed_flows": self.completed_flows,

            "alerts": self.total_alerts,

            "risk": self.risk

        }