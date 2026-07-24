"""
=========================================================
Network Intrusion Detection System (NIDS)

Module : Detection State

Stores runtime memory for detection engines.

=========================================================
"""


from collections import defaultdict





# =====================================================
# Attack Lifecycle State
# =====================================================


active_attacks = {}


attack_history = []



# =====================================================
# Alert ID Generator
# =====================================================


_alert_counter = 0



def next_alert_id():

    global _alert_counter


    _alert_counter += 1


    return _alert_counter





# =====================================================
# Port Scan History
# =====================================================


syn_scan_history = defaultdict(list)


fin_scan_history = defaultdict(list)


null_scan_history = defaultdict(list)


xmas_scan_history = defaultdict(list)





# =====================================================
# ICMP Detection History
# =====================================================


icmp_history = defaultdict(list)


ping_sweep_history = defaultdict(set)





# =====================================================
# Network Activity History
# =====================================================


broadcast_history = defaultdict(list)


arp_history = defaultdict(list)


large_packet_history = defaultdict(list)





# =====================================================
# Protocol Activity History
# =====================================================


dns_history = defaultdict(list)


http_history = defaultdict(list)


ftp_history = defaultdict(list)


ssh_history = defaultdict(list)





# =====================================================
# Reset Detection State
# =====================================================


def reset_state():

    global _alert_counter


    active_attacks.clear()


    attack_history.clear()



    syn_scan_history.clear()

    fin_scan_history.clear()

    null_scan_history.clear()

    xmas_scan_history.clear()



    icmp_history.clear()

    ping_sweep_history.clear()



    broadcast_history.clear()

    arp_history.clear()

    large_packet_history.clear()



    dns_history.clear()

    http_history.clear()

    ftp_history.clear()

    ssh_history.clear()



    _alert_counter = 0