"""
====================================================
Network Intrusion Detection System (NIDS)

Module : Session Object

Represents one IDS monitoring session.

====================================================
"""


from datetime import datetime





class Session:


    def __init__(self,session_id):


        self.session_id=session_id


        self.start_time=datetime.now()


        self.end_time=None


        self.status="ACTIVE"





        # Statistics


        self.total_packets=0


        self.total_flows=0


        self.active_flows=0


        self.completed_flows=0



        self.total_alerts=0


        self.total_warnings=0



        self.risk="LOW"



        self.high_risk=0


        self.medium_risk=0


        self.low_risk=0


        self.critical_risk=0





        # Traffic summary


        self.total_bytes=0


        self.protocols={}





        # Attacks


        self.active_attacks={}


        self.attack_history=[]


        self.unique_attacks={}









# =====================================================
# Packet
# =====================================================


    def add_packet(self):


        self.total_packets+=1







# =====================================================
# Flow Update
# =====================================================


    def update_flows(

            self,

            total,

            active,

            completed

    ):


        self.total_flows=total


        self.active_flows=active


        self.completed_flows=completed








# =====================================================
# Add Attack
# =====================================================


    def add_attack(self,attack):


        self.total_alerts+=1



        key=(

            attack["source_ip"],

            attack["attack_type"]

        )



        self.active_attacks[key]=attack





        name=attack["attack_type"]



        self.unique_attacks.setdefault(

            name,

            0

        )



        self.unique_attacks[name]+=1







# =====================================================
# Update Attack Packets
# =====================================================


    def increment_attack_packet(

            self,

            key

    ):


        if key in self.active_attacks:


            self.active_attacks[key]["packet_count"] +=1








# =====================================================
# Finish Attack
# =====================================================


    def finish_attack(self,attack):


        key=(

            attack["source_ip"],

            attack["attack_type"]

        )



        if key in self.active_attacks:


            finished=self.active_attacks.pop(key)



            self.attack_history.append(

                finished

            )








# =====================================================
# Risk
# =====================================================


    def update_risk(self,risk):


        levels={


            "LOW":1,

            "MEDIUM":2,

            "HIGH":3,

            "CRITICAL":4

        }



        if risk=="LOW":

            self.low_risk+=1


        elif risk=="MEDIUM":

            self.medium_risk+=1


        elif risk=="HIGH":

            self.high_risk+=1


        elif risk=="CRITICAL":

            self.critical_risk+=1





        if levels[risk] > levels[self.risk]:

            self.risk=risk









# =====================================================
# Close
# =====================================================


    def close(self):


        self.end_time=datetime.now()


        self.status="COMPLETED"



        for attack in self.active_attacks.values():

            self.attack_history.append(

                attack

            )



        self.active_attacks.clear()









    @property
    def duration(self):

        end=self.end_time or datetime.now()


        return (

            end -

            self.start_time

        ).total_seconds()





# =====================================================
# Dictionary Format
# =====================================================


    def to_dict(self):


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

            "packets":

                self.total_packets,

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

            "unique_attacks":

                len(self.unique_attacks)

        }





# =====================================================
# Attack Summary
# =====================================================


    def get_attack_summary(self):


        summary = []


        for attack in self.attack_history:


            item = dict(attack)


            item["packets"] = item.get(

                "packet_count",

                0

            )


            summary.append(item)


        return summary
