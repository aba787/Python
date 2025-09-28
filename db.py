
import sqlite3
import os

def get_db():
    conn = sqlite3.connect("alerts.db", check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            message TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Add some sample data if table is empty
    cursor.execute("SELECT COUNT(*) FROM alerts")
    if cursor.fetchone()[0] == 0:
        sample_alerts = [
            ("Normal traffic detected",),
            ("Suspicious activity → Attack",),
            ("Normal packet flow → Normal",),
            ("Large packet detected → Suspicious/Malicious",)
        ]
        cursor.executemany("INSERT INTO alerts (message) VALUES (?)", sample_alerts)
    
    conn.commit()
    conn.close()
