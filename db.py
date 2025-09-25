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
    try:
        conn = sqlite3.connect(DATABASE)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?", (limit,))
        rows = cursor.fetchall()

        alerts = []
        for row in rows:
            alerts.append({
                'id': row['id'],
                'level': row['level'],
                'message': row['message'],
                'timestamp': row['timestamp']
            })

        conn.close()
        print(f"Retrieved {len(alerts)} alerts from database")
        return alerts
    except Exception as e:
        print(f"Error getting alerts: {e}")
        return []

def get_stats():
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()

        cursor.execute("SELECT level, COUNT(*) as count FROM alerts GROUP BY level")
        results = cursor.fetchall()

        stats = {}
        for level, count in results:
            stats[level] = count

        conn.close()
        print(f"Retrieved stats: {stats}")
        return stats
    except Exception as e:
        print(f"Error getting stats: {e}")
        return {}

def clear_alerts():
    conn = get_db_connection()
    conn.execute('DELETE FROM alerts')
    conn.commit()
    conn.close()