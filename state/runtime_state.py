"""
====================================================
Network Intrusion Detection System (NIDS)

Module : Runtime State Manager

Centralized state manager for the frontend communication.
====================================================
"""

import collections

class RuntimeState:
    def __init__(self):
        self.live_packets = collections.deque(maxlen=100)
        self.is_monitoring = False
        self.current_interface = None
        
        # Will be bound to existing structures to avoid duplication
        self.dashboard_statistics = {}
        self.top_hosts = []
        self.protocol_statistics = {}
        
        self.active_attacks = []
        self.attack_history = []

    def set_monitoring(self, status, interface=None):
        """Update the monitoring status and current interface."""
        self.is_monitoring = status
        self.current_interface = interface
        if not status:
            self.live_packets.clear()
            self.active_attacks.clear()

    def add_packet(self, packet):
        """Add a packet to the live packet circular buffer."""
        if "timestamp" in packet and hasattr(packet["timestamp"], "isoformat"):
            packet["timestamp"] = packet["timestamp"].isoformat()
        self.live_packets.append(packet)

    def update_statistics(self, stats):
        """Update dashboard statistics (bind to reference)."""
        self.dashboard_statistics = stats

    def update_risk(self, risk):
        """Update the current risk level."""
        self.dashboard_statistics["risk"] = risk

    def update_top_hosts(self, hosts):
        """Update top communicating hosts."""
        self.top_hosts = hosts

    def update_protocol_statistics(self, protocols):
        """Update protocol counts."""
        self.protocol_statistics = protocols

    def add_attack(self, attack):
        """Add or update an active attack."""
        # Check if already in active attacks
        for i, a in enumerate(self.active_attacks):
            if a.get("alert_id") == attack.get("alert_id"):
                self.active_attacks[i] = attack
                return
        self.active_attacks.append(attack)

    def add_history(self, attack):
        """Move a completed attack to history."""
        # Remove from active attacks
        self.active_attacks = [a for a in self.active_attacks if a.get("alert_id") != attack.get("alert_id")]
        # Add to history
        self.attack_history.insert(0, attack)
        
    def get_dashboard_state(self):
        """Return the overall dashboard state."""
        return {
            "monitoring_status": self.is_monitoring,
            "current_interface": self.current_interface,
            "statistics": self.dashboard_statistics
        }

    def get_live_packets(self):
        return list(self.live_packets)

    def get_active_attacks(self):
        return self.active_attacks

    def get_attack_history(self):
        return self.attack_history

    def get_top_hosts(self, count=10):
        return self.top_hosts[:count]

    def get_statistics(self):
        # Merge all stats for comprehensive endpoint
        stats = self.dashboard_statistics.copy()
        stats["protocol_counts"] = self.protocol_statistics
        return stats

# Global Singleton Instance
state_manager = RuntimeState()
