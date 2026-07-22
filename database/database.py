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





    # Flows

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





    # Alerts

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





    # Packets

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

        packet_size INTEGER

    )

    """)



    conn.commit()


    conn.close()


    print(
        "Database Tables Created Successfully."
    )