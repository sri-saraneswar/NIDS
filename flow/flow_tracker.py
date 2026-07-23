"""
=========================================================
Network Intrusion Detection System (NIDS)

Module : Flow Tracker

Tracks bidirectional network flows.

=========================================================
"""


from datetime import datetime


from config import FLOW_TIMEOUT


from flow.flow import Flow





active_flows = {}

completed_flows = {}





# =====================================================
# Generate Flow ID
# =====================================================


def generate_flow_id(packet):


    protocol = packet["protocol"]



    # ARP has no ports

    if protocol == "ARP":


        hosts = sorted([

            packet["src_ip"],

            packet["dst_ip"]

        ])


        return (

            f"{hosts[0]}-"

            f"{hosts[1]}-ARP"

        )





    endpoint1 = (

        packet["src_ip"],

        packet.get("src_port",0)

    )


    endpoint2 = (

        packet["dst_ip"],

        packet.get("dst_port",0)

    )



    endpoints = sorted([

        endpoint1,

        endpoint2

    ])




    return (

        f"{endpoints[0][0]}:"

        f"{endpoints[0][1]}-"

        f"{endpoints[1][0]}:"

        f"{endpoints[1][1]}-"

        f"{protocol}"

    )







# =====================================================
# Update Flow
# =====================================================


def update_flow(packet):


    flow_id = generate_flow_id(packet)



    now = datetime.now()





    # Existing flow

    if flow_id in active_flows:


        flow = active_flows[flow_id]


        flow.update(packet)


        return flow





    # New flow


    flow = Flow(

        flow_id,

        packet["src_ip"],

        packet["dst_ip"],

        packet.get("src_port",0),

        packet.get("dst_port",0),

        packet["protocol"]

    )



    flow.packet_count = 1


    flow.bytes = packet.get(

        "packet_size",

        0

    )


    flow.start_time = now

    flow.last_seen = now



    active_flows[flow_id] = flow



    return flow





# =====================================================
# Cleanup
# =====================================================


def cleanup_flows():


    now = datetime.now()


    expired=[]




    for flow_id,flow in active_flows.items():


        idle = (

            now -

            flow.last_seen

        ).total_seconds()




        if idle >= FLOW_TIMEOUT:


            flow.close()


            completed_flows[flow_id]=flow


            expired.append(flow_id)




    for flow_id in expired:


        del active_flows[flow_id]







# =====================================================
# Statistics
# =====================================================


def get_total_flow_count():

    return (

        len(active_flows)

        +

        len(completed_flows)

    )





def get_active_flow_count():

    return len(active_flows)





def get_completed_flow_count():

    return len(completed_flows)







def get_completed_flows():

    return list(

        completed_flows.values()

    )







def remove_completed_flow(flow_id):


    if flow_id in completed_flows:

        del completed_flows[flow_id]







def get_all_flows():


    return (

        list(active_flows.values())

        +

        list(completed_flows.values())

    )







# =====================================================
# Reset
# =====================================================


def reset_flows():


    active_flows.clear()


    completed_flows.clear()