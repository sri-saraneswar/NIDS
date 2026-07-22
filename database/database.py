"""
====================================================
Network Intrusion Detection System (NIDS)

Module : Database Manager

Uses SQLite for storing IDS information.

====================================================
"""


import sqlite3



from config import DATABASE_NAME





# ==========================================
# Connection
# ==========================================

def get_connection():

    return sqlite3.connect(
        DATABASE_NAME
    )





# ==========================================
# Create Tables
# ==========================================

def create_database():


    conn = get_connection()


    cursor = conn.cursor()



    # Sessions

    cursor.execute("""
    
    CREATE TABLE IF NOT EXISTS sessions(

        session_id TEXT PRIMARY KEY,

        start_time TEXT,

        end_time TEXT,

        duration REAL,

        packets INTEGER,

        flows INTEGER,

        active_flows INTEGER,

        completed_flows INTEGER,

        alerts INTEGER,

        risk TEXT,

        status TEXT

    )

    """)

    # ---------------- Flows ----------------

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

    # ---------------- Alerts ----------------

    cursor.execute("""

    CREATE TABLE IF NOT EXISTS alerts(

        alert_id INTEGER PRIMARY KEY AUTOINCREMENT,

        session_id TEXT,

        flow_id TEXT,

        timestamp TEXT,

        severity TEXT,

        attack TEXT,

        source_ip TEXT,

        destination_ip TEXT,

        description TEXT

    )

    """)

    # ---------------- Packets ----------------

    cursor.execute("""

    CREATE TABLE IF NOT EXISTS packets(

        packet_id INTEGER PRIMARY KEY AUTOINCREMENT,

        session_id TEXT,

        flow_id TEXT,

        timestamp TEXT,

        source_ip TEXT,

        destination_ip TEXT,

        source_port INTEGER,

        destination_port INTEGER,

        protocol TEXT,

        packet_size INTEGER,

        information TEXT

    )

    """)

    conn.commit()

    conn.close()

    print("Database Initialized Successfully.")


# ==================================================
# Save Session
# ==================================================

def save_session(summary):

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute("""

    INSERT OR REPLACE INTO sessions
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)

    """, (

        summary["session_id"],

        str(summary["start_time"]),

        str(summary["end_time"]),

        summary["duration"],

        summary["packets"],

        summary["flows"],

        summary["active_flows"],

        summary["completed_flows"],

        summary["alerts"],

        summary["risk"],

        summary["status"]

    ))

    conn.commit()

    conn.close()


# ==================================================
# Save Packet
# ==================================================

def save_packet(packet_info, session_id):

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute("""

    INSERT INTO packets(

        session_id,

        flow_id,

        timestamp,

        source_ip,

        destination_ip,

        source_port,

        destination_port,

        protocol,

        packet_size,

        information

    )

    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)

    """, (

        session_id,

        packet_info.get("flow_id"),

        str(packet_info["timestamp"]),

        packet_info["src_ip"],

        packet_info["dst_ip"],

        packet_info["src_port"],

        packet_info["dst_port"],

        packet_info["protocol"],

        packet_info["packet_size"],

        ""

    ))

    conn.commit()

    conn.close()


# ==================================================
# Save Flow
# ==================================================

def save_flow(flow, session_id):

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute("""

    INSERT OR REPLACE INTO flows
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)

    """, (

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


# ==================================================
# Save Alert
# ==================================================

def save_alert(packet_info, result, session_id):

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute("""

    INSERT INTO alerts(

        session_id,

        flow_id,

        timestamp,

        severity,

        attack,

        source_ip,

        destination_ip,

        description

    )

    VALUES (?, ?, ?, ?, ?, ?, ?, ?)

    """, (

        session_id,

        packet_info.get("flow_id"),

        str(packet_info["timestamp"]),

        result["severity"],

        result["attack"],

        packet_info["src_ip"],

        packet_info["dst_ip"],

        result["reason"]

    ))

    conn.commit()

    conn.close()
