
import sqlite3
import json
from datetime import datetime

DATABASE = 'alerts.db'

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            level TEXT NOT NULL,
            message TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

def add_alert(level, message):
    conn = get_db_connection()
    conn.execute(
        'INSERT INTO alerts (level, message) VALUES (?, ?)',
        (level, message)
    )
    conn.commit()
    conn.close()

def get_alerts(limit=100):
    conn = get_db_connection()
    alerts = conn.execute(
        'SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?',
        (limit,)
    ).fetchall()
    conn.close()
    
    return [dict(alert) for alert in alerts]

def get_stats():
    conn = get_db_connection()
    stats = conn.execute(
        'SELECT level, COUNT(*) as count FROM alerts GROUP BY level'
    ).fetchall()
    conn.close()
    
    return {stat['level']: stat['count'] for stat in stats}

def clear_alerts():
    conn = get_db_connection()
    conn.execute('DELETE FROM alerts')
    conn.commit()
    conn.close()
