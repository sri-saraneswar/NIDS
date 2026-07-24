"""
====================================================
Network Intrusion Detection System (NIDS)

Module : Session Object

Represents one IDS monitoring session.

Tracks:
    Packets
    Flows
    Attacks
    Protocols
    Risk Levels
    Bytes

====================================================
"""


from datetime import datetime





class Session:
    """Represents a single IDS monitoring session."""


    def __init__(self, session_id):
        """Initialize a new monitoring session."""

        self.session_id = session_id

        self.start_time = datetime.now()

        self.end_time = None

        self.status = "ACTIVE"

        self.interface = None



        # ── Packet Statistics ──────────────────────

        self.total_packets = 0

        self.total_bytes = 0



        # ── Flow Statistics ────────────────────────

        self.total_flows = 0

        self.active_flows = 0

        self.completed_flows = 0



        # ── Alert Statistics ───────────────────────

        self.total_alerts = 0

        self.total_warnings = 0



        # ── Risk Tracking ──────────────────────────

        self.risk = "LOW"

        self.critical_risk = 0

        self.high_risk = 0

        self.medium_risk = 0

        self.low_risk = 0



        # ── Protocol Statistics ────────────────────

        self.protocol_stats = {}



        # ── Attack Tracking ────────────────────────

        self.active_attacks = {}

        self.attack_history = []

        self.unique_attacks = {}





    # =====================================================
    # Packet
    # =====================================================


    def add_packet(self):
        """Increment the total packet count."""

        self.total_packets += 1





    # =====================================================
    # Protocol and Byte Tracking
    # =====================================================


    def update_protocol(self, protocol, packet_size):
        """
        Track protocol distribution and byte totals.

        Args:
            protocol: Protocol name string.
            packet_size: Packet size in bytes.
        """

        self.total_bytes += packet_size

        self.protocol_stats.setdefault(
            protocol, 0
        )

        self.protocol_stats[protocol] += 1





    # =====================================================
    # Flow Update
    # =====================================================


    def update_flows(
            self,
            total,
            active,
            completed
    ):
        """Update flow statistics."""

        self.total_flows = total

        self.active_flows = active

        self.completed_flows = completed





    # =====================================================
    # Add Attack
    # =====================================================


    def add_attack(self, attack):
        """Register a new detected attack."""

        self.total_alerts += 1


        key = (
            attack["source_ip"],
            attack["attack_type"]
        )


        self.active_attacks[key] = attack


        name = attack["attack_type"]

        self.unique_attacks.setdefault(
            name, 0
        )

        self.unique_attacks[name] += 1





    # =====================================================
    # Update Attack Packets
    # =====================================================


    def increment_attack_packet(
            self,
            key
    ):
        """Increment the packet count for an active attack."""

        if key in self.active_attacks:

            self.active_attacks[key]["packet_count"] += 1





    # =====================================================
    # Finish Attack
    # =====================================================


    def finish_attack(self, attack):
        """Move an active attack to the history list."""

        key = (
            attack["source_ip"],
            attack["attack_type"]
        )


        if key in self.active_attacks:

            finished = self.active_attacks.pop(key)

            self.attack_history.append(
                finished
            )





    # =====================================================
    # Risk
    # =====================================================


    def update_risk(self, risk):
        """Update risk level and severity counters."""

        levels = {
            "LOW": 1,
            "MEDIUM": 2,
            "HIGH": 3,
            "CRITICAL": 4
        }


        if risk == "LOW":
            self.low_risk += 1

        elif risk == "MEDIUM":
            self.medium_risk += 1

        elif risk == "HIGH":
            self.high_risk += 1

        elif risk == "CRITICAL":
            self.critical_risk += 1


        if levels.get(risk, 0) > levels.get(
            self.risk, 0
        ):
            self.risk = risk





    # =====================================================
    # Close
    # =====================================================


    def close(self):
        """Close the monitoring session."""

        self.end_time = datetime.now()

        self.status = "COMPLETED"


        # Move remaining active attacks to history

        for attack in self.active_attacks.values():

            self.attack_history.append(
                attack
            )


        self.active_attacks.clear()





    # =====================================================
    # Duration
    # =====================================================


    @property
    def duration(self):
        """Calculate session duration in seconds."""

        end = self.end_time or datetime.now()

        return (
            end - self.start_time
        ).total_seconds()





    # =====================================================
    # Dictionary Format
    # =====================================================


    def to_dict(self):
        """Convert session data to dictionary for storage and display."""

        return {

            "session_id":
                self.session_id,

            "start_time":
                self.start_time,

            "end_time":
                self.end_time,

            "duration":
                self.duration,

            "status":
                self.status,

            "interface":
                self.interface,

            "packets":
                self.total_packets,

            "total_bytes":
                self.total_bytes,

            "flows":
                self.total_flows,

            "active_flows":
                self.active_flows,

            "completed_flows":
                self.completed_flows,

            "alerts":
                self.total_alerts,

            "warnings":
                self.total_warnings,

            "risk":
                self.risk,

            "risk_stats": {
                "CRITICAL": self.critical_risk,
                "HIGH": self.high_risk,
                "MEDIUM": self.medium_risk,
                "LOW": self.low_risk
            },

            "protocol_stats":
                dict(self.protocol_stats),

            "unique_attacks":
                len(self.unique_attacks),

            "attack_types":
                dict(self.unique_attacks)

        }





    # =====================================================
    # Attack Summary
    # =====================================================


    def get_attack_summary(self):
        """
        Get a summary list of all attacks in the session.

        Returns:
            List of attack dicts with computed fields.
        """

        summary = []


        for attack in self.attack_history:

            item = dict(attack)

            item["packets"] = item.get(
                "packet_count", 0
            )

            summary.append(item)


        return summary
