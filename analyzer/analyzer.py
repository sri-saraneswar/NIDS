"""
====================================================
Network Intrusion Detection System (NIDS)

Module : Packet Analyzer

Connects:
- Flow Tracking
- Detection Engine
- Session Tracking
- Console Output

====================================================
"""


from flow.flow_tracker import (

    update_flow,

    get_total_flow_count,

    get_active_flow_count,

    get_completed_flow_count

)



from detection.detection import detect



from console.console_manager import (

    display_live_status,

    display_alert

)



from detection.statistics import (

    security_summary,

    should_print_summary

)



from session.session_manager import (

    update_packet,

    update_flows,

    update_alert,

    update_risk

)





# Packet counter

packet_id = 0






def analyze_packet(packet_info):


    global packet_id



    packet_id += 1





    # ==========================================
    # 1. FLOW UPDATE
    # ==========================================


    flow = update_flow(packet_info)



    packet_info["flow_id"] = flow.flow_id





    # ==========================================
    # 2. SESSION UPDATE
    # ==========================================


    update_packet()



    update_flows(

        get_total_flow_count(),

        get_active_flow_count(),

        get_completed_flow_count()

    )





    # ==========================================
    # 3. DETECTION
    # ==========================================


    result = detect(packet_info)





    # ==========================================
    # 4. ALERT HANDLING
    # ==========================================


    if result["status"] == "ALERT":


        update_alert()



        update_risk(

            result["severity"]

        )



        display_alert(

            packet_info,

            result

        )



    else:


        display_live_status()





    # ==========================================
    # 5. PERIODIC SECURITY SUMMARY
    # ==========================================


    if should_print_summary():


        security_summary()