"""
====================================================
Network Intrusion Detection System (NIDS)

Module : Database Manager

Stores:

1. Sessions
2. Attack Sessions
3. Alerts
4. Flows
5. Suspicious Packets

====================================================
"""


import sqlite3


from config import DATABASE_NAME





# =====================================================
# Database Connection
# =====================================================


def get_connection():


    conn = sqlite3.connect(

        DATABASE_NAME

    )


    conn.execute(

        "PRAGMA foreign_keys = ON"

    )


    return conn






# =====================================================
# Initialize Database
# =====================================================


def create_database():


    conn = get_connection()

    cursor = conn.cursor()



    # =================================================
    # Sessions Table
    # =================================================


    cursor.execute("""

    CREATE TABLE IF NOT EXISTS sessions(

        session_id TEXT PRIMARY KEY,

        start_time TEXT,

        end_time TEXT,

        duration REAL,

        status TEXT,

        total_packets INTEGER,

        total_flows INTEGER,

        active_flows INTEGER,

        completed_flows INTEGER,

        total_alerts INTEGER,

        total_warnings INTEGER,

        highest_risk TEXT,

        unique_attacks INTEGER

    )

    """)





    # =================================================
    # Attack Sessions Table
    # =================================================


    cursor.execute("""

    CREATE TABLE IF NOT EXISTS attacks(

        attack_id TEXT PRIMARY KEY,

        session_id TEXT,

        attack_type TEXT,

        severity TEXT,

        source_ip TEXT,

        destination_ip TEXT,

        start_time TEXT,

        end_time TEXT,

        duration REAL,

        packet_count INTEGER,

        attack_details TEXT

    )

    """)






    # =================================================
    # Alert Table
    # =================================================


    cursor.execute("""

    CREATE TABLE IF NOT EXISTS alerts(

        alert_id INTEGER PRIMARY KEY AUTOINCREMENT,

        session_id TEXT,

        attack_id TEXT,

        timestamp TEXT,

        severity TEXT,

        attack_type TEXT,

        source_ip TEXT,

        destination_ip TEXT,

        message TEXT

    )

    """)






    # =================================================
    # Flow Table
    # =================================================


    cursor.execute("""

    CREATE TABLE IF NOT EXISTS flows(

        flow_id TEXT PRIMARY KEY,

        session_id TEXT,

        src_ip TEXT,

        dst_ip TEXT,

        src_port INTEGER,

        dst_port INTEGER,

        protocol TEXT,

        packets INTEGER,

        bytes INTEGER,

        duration REAL,

        status TEXT

    )

    """)







    # =================================================
    # Suspicious Packet Table
    # =================================================


    cursor.execute("""

    CREATE TABLE IF NOT EXISTS suspicious_packets(

        packet_id INTEGER PRIMARY KEY AUTOINCREMENT,

        session_id TEXT,

        attack_id TEXT,

        timestamp TEXT,

        source_ip TEXT,

        destination_ip TEXT,

        source_port INTEGER,

        destination_port INTEGER,

        protocol TEXT,

        packet_size INTEGER,

        description TEXT

    )

    """)


    # =================================================
    # Statistics Table
    # =================================================


    cursor.execute("""

    CREATE TABLE IF NOT EXISTS statistics(

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        session_id TEXT,

        protocol_stats TEXT,

        attack_stats TEXT,

        risk_stats TEXT,

        top_hosts TEXT

    )

    """)



    conn.commit()

    conn.close()



    print(
        "Database Initialized Successfully"
    )








# =====================================================
# Save Session
# =====================================================


def save_session(summary):


    conn = get_connection()

    cursor = conn.cursor()



    cursor.execute("""

    INSERT OR REPLACE INTO sessions

    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)

    """,

    (

        summary["session_id"],


        str(
            summary["start_time"]
        ),


        str(
            summary["end_time"]
        ),


        summary["duration"],


        summary["status"],


        summary["packets"],


        summary["flows"],


        summary["active_flows"],


        summary["completed_flows"],


        summary["alerts"],


        summary["warnings"],


        summary["risk"],


        summary["unique_attacks"]

    ))



    conn.commit()

    conn.close()







# =====================================================
# Save Completed Attacks
# =====================================================


def save_attacks(session_id, attacks):


    conn = get_connection()

    cursor = conn.cursor()



    for attack in attacks:


        cursor.execute("""

        INSERT OR REPLACE INTO attacks

        VALUES(?,?,?,?,?,?,?,?,?,?,?)

        """,

        (

            attack["alert_id"],


            session_id,


            attack["attack_type"],


            attack["severity"],


            attack["source_ip"],


            attack["destination_ip"],


            str(
                attack.get(
                    "start_time"
                )
            ),


            str(
                attack.get(
                    "end_time"
                )
            ),


            attack.get(
                "duration",
                0
            ),


            attack.get(
                "packet_count",
                0
            ),


            str(
                attack.get(
                    "details",
                    {}
                )
            )

        ))



    conn.commit()

    conn.close()








# =====================================================
# Save Alert
# =====================================================


def save_alert(session_id, attack):


    conn = get_connection()

    cursor = conn.cursor()



    cursor.execute("""

    INSERT INTO alerts

    (

    session_id,

    attack_id,

    timestamp,

    severity,

    attack_type,

    source_ip,

    destination_ip,

    message

    )

    VALUES(?,?,?,?,?,?,?,?)

    """,

    (

        session_id,


        attack["alert_id"],


        str(
            attack["start_time"]
        ),


        attack["severity"],


        attack["attack_type"],


        attack["source_ip"],


        attack["destination_ip"],


        attack["attack_type"]

        +
        " Detected"

    ))



    conn.commit()

    conn.close()







# =====================================================
# Save Flow
# =====================================================


def save_flow(session_id, flow):


    conn = get_connection()

    cursor = conn.cursor()



    cursor.execute("""

    INSERT OR REPLACE INTO flows

    VALUES(?,?,?,?,?,?,?,?,?,?,?)

    """,

    (

        flow.flow_id,


        session_id,


        flow.src_ip,


        flow.dst_ip,


        flow.src_port,


        flow.dst_port,


        flow.protocol,


        flow.packet_count,


        flow.bytes,


        flow.duration,


        flow.status

    ))



    conn.commit()

    conn.close()







# =====================================================
# Save Suspicious Packet
# =====================================================


def save_suspicious_packet(

        session_id,

        attack_id,

        packet

):


    conn = get_connection()

    cursor = conn.cursor()



    cursor.execute("""

    INSERT INTO suspicious_packets

    (

    session_id,

    attack_id,

    timestamp,

    source_ip,

    destination_ip,

    source_port,

    destination_port,

    protocol,

    packet_size,

    description

    )

    VALUES(?,?,?,?,?,?,?,?,?,?)

    """,

    (

        session_id,


        attack_id,


        str(
            packet["timestamp"]
        ),


        packet["src_ip"],


        packet["dst_ip"],


        packet.get(
            "src_port",
            0
        ),


        packet.get(
            "dst_port",
            0
        ),


        packet["protocol"],


        packet["packet_size"],


        "Suspicious Packet"

    ))



    conn.commit()

    conn.close()



# =====================================================
# Save Statistics
# =====================================================


def save_statistics(session_id, stats):
    """
    Save session statistics to the database.

    Stats are stored as JSON strings for flexibility.

    Args:
        session_id: The session identifier.
        stats: Dictionary containing protocol_stats,
               attack_stats, risk_stats, top_hosts.
    """

    import json


    conn = get_connection()

    cursor = conn.cursor()


    cursor.execute("""

    INSERT INTO statistics

    (
    session_id,
    protocol_stats,
    attack_stats,
    risk_stats,
    top_hosts
    )

    VALUES(?,?,?,?,?)

    """,

    (

        session_id,

        json.dumps(
            stats.get("protocol_stats", {})
        ),

        json.dumps(
            stats.get("attack_types", {})
        ),

        json.dumps(
            stats.get("risk_stats", {})
        ),

        json.dumps(
            stats.get("top_hosts", [])
        )

    ))


    conn.commit()

    conn.close()