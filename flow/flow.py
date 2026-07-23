"""
=========================================================
Network Intrusion Detection System (NIDS)

Module : Flow Object

Represents one bidirectional network communication flow.

=========================================================
"""


from datetime import datetime



class Flow:


    def __init__(

        self,

        flow_id,

        src_ip,

        dst_ip,

        src_port,

        dst_port,

        protocol

    ):


        self.flow_id = flow_id


        self.src_ip = src_ip

        self.dst_ip = dst_ip


        self.src_port = src_port

        self.dst_port = dst_port


        self.protocol = protocol



        # Statistics

        self.packet_count = 0

        self.bytes = 0



        self.start_time = datetime.now()

        self.last_seen = datetime.now()

        self.end_time = None


        self.duration = 0



        self.status = "ACTIVE"



        # Traffic direction

        self.forward_packets = 0

        self.reverse_packets = 0



        # TCP state

        self.tcp_state = "UNKNOWN"





    # ==========================================
    # Update Flow
    # ==========================================

    def update(self, packet):


        self.packet_count += 1


        self.bytes += packet.get(

            "packet_size",

            0

        )


        self.last_seen = datetime.now()



        self.update_tcp_state(packet)





    # ==========================================
    # TCP State Tracking
    # ==========================================

    def update_tcp_state(self, packet):


        if self.protocol != "TCP":

            return



        flags = packet.get(

            "flags",

            ""

        )



        if flags == "S":

            self.tcp_state = "SYN"



        elif "SA" in flags:

            self.tcp_state = "ESTABLISHED"



        elif "F" in flags:

            self.tcp_state = "FIN"



        elif "R" in flags:

            self.tcp_state = "RESET"





    # ==========================================
    # Close Flow
    # ==========================================

    def close(self):


        self.end_time = datetime.now()



        self.duration = (

            self.end_time -

            self.start_time

        ).total_seconds()



        self.status = "COMPLETED"





    # ==========================================
    # Database Format
    # ==========================================

    def to_dict(self):


        return {


            "flow_id":
                self.flow_id,


            "src_ip":
                self.src_ip,


            "dst_ip":
                self.dst_ip,


            "src_port":
                self.src_port,


            "dst_port":
                self.dst_port,


            "protocol":
                self.protocol,


            "packets":
                self.packet_count,


            "bytes":
                self.bytes,


            "duration":
                self.duration,


            "tcp_state":
                self.tcp_state,


            "status":
                self.status

        }