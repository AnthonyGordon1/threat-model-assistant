import os
import json
from datetime import datetime
from app.db.pgvector import get_connection

def setup_security_logs_table():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS security_events (
            id SERIAL PRIMARY KEY,
            event_type VARCHAR(50) NOT NULL,
            ip_address VARCHAR(50),
            input_text TEXT,
            pattern_matched VARCHAR(200),
            status_code INTEGER,
            timestamp TIMESTAMP DEFAULT NOW()
        );
    """)
    conn.commit()
    cursor.close()
    conn.close()

def log_security_event(event_type: str, ip_address: str = None, input_text: str = None, pattern_matched: str = None, status_code: int = None):
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO security_events (event_type, ip_address, input_text, pattern_matched, status_code)
            VALUES (%s, %s, %s, %s, %s)
        """, (event_type, ip_address, input_text[:500] if input_text else None, pattern_matched, status_code))
        conn.commit()
        cursor.close()
        conn.close()
    except Exception as e:
        print(f"Failed to log security event: {e}")