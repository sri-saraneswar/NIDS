"""
====================================================
Network Intrusion Detection System (NIDS)
Module : Flow Class
Description:
Represents a single communication flow.
====================================================
"""

from datetime import datetime


class Flow:
    """
    Represents one network communication.
    """

    def __init__(
        self,
        flow_id,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        protocol,
        packet_size
    ):

        self.flow_id = flow_id

        self.src_ip = src_ip
        self.dst_ip = dst_ip

        self.src_port = src_port
        self.dst_port = dst_port

        self.protocol = protocol

        self.packet_count = 1

        self.bytes = packet_size

        self.start_time = datetime.now()

        self.last_seen = self.start_time

        self.end_time = None

        self.status = "ACTIVE"

        self.duration = 0

        self.average_packet_size = packet_size

        self.packet_rate = 0

        self.byte_rate = 0

        self.alerts = []

        self.risk = "LOW"

    # ----------------------------------------
    # Update Flow
    # ----------------------------------------

    def update(self, packet_size):

        self.packet_count += 1

        self.bytes += packet_size

        self.last_seen = datetime.now()

        self.calculate_statistics()

    # ----------------------------------------
    # Calculate Statistics
    # ----------------------------------------

    def calculate_statistics(self):

        duration = (

            self.last_seen -

            self.start_time

        ).total_seconds()

        if duration <= 0:

            duration = 1

        self.duration = duration

        self.average_packet_size = (

            self.bytes /

            self.packet_count

        )

        self.packet_rate = (

            self.packet_count /

            duration

        )

        self.byte_rate = (

            self.bytes /

            duration

        )

    # ----------------------------------------
    # Close Flow
    # ----------------------------------------

    def close(self):

        self.end_time = datetime.now()

        self.status = "COMPLETED"

        self.calculate_statistics()

    # ----------------------------------------
    # Convert to Dictionary
    # ----------------------------------------

    def to_dict(self):

        return {

            "flow_id": self.flow_id,

            "src_ip": self.src_ip,

            "dst_ip": self.dst_ip,

            "src_port": self.src_port,

            "dst_port": self.dst_port,

            "protocol": self.protocol,

            "packet_count": self.packet_count,

            "bytes": self.bytes,

            "duration": self.duration,

            "average_packet_size":
                self.average_packet_size,

            "packet_rate":
                self.packet_rate,

            "byte_rate":
                self.byte_rate,

            "status":
                self.status,

            "risk":
                self.risk

        }