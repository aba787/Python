
import sqlite3
import psycopg2
import os
import json
from datetime import datetime, timedelta
import logging

# Database configuration
USE_POSTGRES = os.getenv('DATABASE_URL') is not None
DATABASE = 'alerts.db'  # SQLite fallback

class DatabaseManager:
    def __init__(self):
        self.use_postgres = USE_POSTGRES
        self.connection_params = None
        if self.use_postgres:
            self.connection_params = os.getenv('DATABASE_URL')
            self.init_postgres_db()
        else:
            self.init_sqlite_db()
    
    def get_connection(self):
        """Get database connection"""
        if self.use_postgres:
            return psycopg2.connect(self.connection_params)
        else:
            conn = sqlite3.connect(DATABASE)
            conn.row_factory = sqlite3.Row
            return conn
    
    def init_postgres_db(self):
        """Initialize PostgreSQL database"""
        try:
            conn = psycopg2.connect(self.connection_params)
            cursor = conn.cursor()
            
            # Create alerts table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS alerts (
                    id SERIAL PRIMARY KEY,
                    level VARCHAR(10) NOT NULL,
                    message TEXT NOT NULL,
                    source_ip INET,
                    destination_ip INET,
                    protocol VARCHAR(10),
                    port INTEGER,
                    confidence REAL,
                    threat_type VARCHAR(50),
                    anomaly_score REAL,
                    correlation_id UUID,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    acknowledged BOOLEAN DEFAULT FALSE,
                    false_positive BOOLEAN DEFAULT FALSE
                )
            ''')
            
            # Create threat intelligence table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS threat_intelligence (
                    id SERIAL PRIMARY KEY,
                    indicator VARCHAR(255) NOT NULL,
                    indicator_type VARCHAR(20) NOT NULL,
                    threat_type VARCHAR(50),
                    confidence INTEGER,
                    source VARCHAR(100),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP,
                    UNIQUE(indicator, indicator_type)
                )
            ''')
            
            # Create correlation rules table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS correlation_rules (
                    id SERIAL PRIMARY KEY,
                    rule_name VARCHAR(100) NOT NULL,
                    rule_query TEXT NOT NULL,
                    severity VARCHAR(10) NOT NULL,
                    time_window INTEGER DEFAULT 300,
                    threshold INTEGER DEFAULT 5,
                    enabled BOOLEAN DEFAULT TRUE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Create incident table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS incidents (
                    id SERIAL PRIMARY KEY,
                    title VARCHAR(200) NOT NULL,
                    description TEXT,
                    severity VARCHAR(10) NOT NULL,
                    status VARCHAR(20) DEFAULT 'open',
                    assigned_to VARCHAR(100),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    resolved_at TIMESTAMP
                )
            ''')
            
            # Create indexes for performance
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_level ON alerts(level)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_source_ip ON alerts(source_ip)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_threat_intel_indicator ON threat_intelligence(indicator)')
            
            conn.commit()
            conn.close()
            print("PostgreSQL database initialized successfully")
            
        except Exception as e:
            print(f"Error initializing PostgreSQL: {e}")
            # Fallback to SQLite
            self.use_postgres = False
            self.init_sqlite_db()
    
    def init_sqlite_db(self):
        """Initialize SQLite database"""
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # Create enhanced alerts table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                level TEXT NOT NULL,
                message TEXT NOT NULL,
                source_ip TEXT,
                destination_ip TEXT,
                protocol TEXT,
                port INTEGER,
                confidence REAL,
                threat_type TEXT,
                anomaly_score REAL,
                correlation_id TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                acknowledged INTEGER DEFAULT 0,
                false_positive INTEGER DEFAULT 0
            )
        ''')
        
        # Create threat intelligence table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_intelligence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                indicator TEXT NOT NULL,
                indicator_type TEXT NOT NULL,
                threat_type TEXT,
                confidence INTEGER,
                source TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                expires_at DATETIME,
                UNIQUE(indicator, indicator_type)
            )
        ''')
        
        # Create correlation rules table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS correlation_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_name TEXT NOT NULL,
                rule_query TEXT NOT NULL,
                severity TEXT NOT NULL,
                time_window INTEGER DEFAULT 300,
                threshold INTEGER DEFAULT 5,
                enabled INTEGER DEFAULT 1,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create incident table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                description TEXT,
                severity TEXT NOT NULL,
                status TEXT DEFAULT 'open',
                assigned_to TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                resolved_at DATETIME
            )
        ''')
        
        conn.commit()
        conn.close()
        print("SQLite database initialized successfully")

# Initialize database manager
db_manager = DatabaseManager()

def init_db():
    """Initialize database"""
    # Database is already initialized in DatabaseManager constructor
    pass

def add_alert(level, message, source_ip=None, destination_ip=None, protocol=None, 
              port=None, confidence=None, threat_type=None, anomaly_score=None, correlation_id=None):
    """Add enhanced alert to database"""
    try:
        conn = db_manager.get_connection()
        cursor = conn.cursor()
        
        if db_manager.use_postgres:
            cursor.execute('''
                INSERT INTO alerts (level, message, source_ip, destination_ip, protocol, 
                                  port, confidence, threat_type, anomaly_score, correlation_id)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ''', (level, message, source_ip, destination_ip, protocol, port, 
                 confidence, threat_type, anomaly_score, correlation_id))
        else:
            cursor.execute('''
                INSERT INTO alerts (level, message, source_ip, destination_ip, protocol,
                                  port, confidence, threat_type, anomaly_score, correlation_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (level, message, source_ip, destination_ip, protocol, port,
                 confidence, threat_type, anomaly_score, correlation_id))
        
        conn.commit()
        conn.close()
        
    except Exception as e:
        print(f"Error adding alert: {e}")

def get_alerts(limit=100, filters=None):
    """Get alerts with optional filtering"""
    try:
        conn = db_manager.get_connection()
        cursor = conn.cursor()
        
        query = "SELECT * FROM alerts"
        params = []
        
        if filters:
            conditions = []
            if filters.get('level'):
                conditions.append("level = %s" if db_manager.use_postgres else "level = ?")
                params.append(filters['level'])
            if filters.get('start_time'):
                conditions.append("timestamp >= %s" if db_manager.use_postgres else "timestamp >= ?")
                params.append(filters['start_time'])
            if filters.get('end_time'):
                conditions.append("timestamp <= %s" if db_manager.use_postgres else "timestamp <= ?")
                params.append(filters['end_time'])
            
            if conditions:
                query += " WHERE " + " AND ".join(conditions)
        
        query += " ORDER BY timestamp DESC"
        if limit:
            query += f" LIMIT {limit}"
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        
        alerts = []
        for row in rows:
            if db_manager.use_postgres:
                alert = {
                    'id': row[0], 'level': row[1], 'message': row[2],
                    'source_ip': str(row[3]) if row[3] else None,
                    'destination_ip': str(row[4]) if row[4] else None,
                    'protocol': row[5], 'port': row[6], 'confidence': row[7],
                    'threat_type': row[8], 'anomaly_score': row[9],
                    'correlation_id': str(row[10]) if row[10] else None,
                    'timestamp': row[11].isoformat() if row[11] else None,
                    'acknowledged': row[12], 'false_positive': row[13]
                }
            else:
                alert = {
                    'id': row['id'], 'level': row['level'], 'message': row['message'],
                    'source_ip': row['source_ip'], 'destination_ip': row['destination_ip'],
                    'protocol': row['protocol'], 'port': row['port'], 'confidence': row['confidence'],
                    'threat_type': row['threat_type'], 'anomaly_score': row['anomaly_score'],
                    'correlation_id': row['correlation_id'], 'timestamp': row['timestamp'],
                    'acknowledged': row['acknowledged'], 'false_positive': row['false_positive']
                }
            alerts.append(alert)
        
        conn.close()
        return alerts
        
    except Exception as e:
        print(f"Error getting alerts: {e}")
        return []

def get_stats():
    """Get enhanced statistics"""
    try:
        conn = db_manager.get_connection()
        cursor = conn.cursor()
        
        # Basic level stats
        cursor.execute("SELECT level, COUNT(*) as count FROM alerts GROUP BY level")
        results = cursor.fetchall()
        
        stats = {}
        for result in results:
            if db_manager.use_postgres:
                stats[result[0]] = result[1]
            else:
                stats[result[0]] = result[1]
        
        # Add threat type stats
        cursor.execute("SELECT threat_type, COUNT(*) as count FROM alerts WHERE threat_type IS NOT NULL GROUP BY threat_type")
        threat_results = cursor.fetchall()
        
        threat_stats = {}
        for result in threat_results:
            if db_manager.use_postgres:
                threat_stats[result[0]] = result[1]
            else:
                threat_stats[result[0]] = result[1]
        
        stats['threat_types'] = threat_stats
        
        # Add time-based stats (last 24 hours)
        yesterday = datetime.now() - timedelta(days=1)
        cursor.execute(
            "SELECT COUNT(*) FROM alerts WHERE timestamp >= %s" if db_manager.use_postgres 
            else "SELECT COUNT(*) FROM alerts WHERE timestamp >= ?",
            (yesterday,)
        )
        stats['last_24h'] = cursor.fetchone()[0]
        
        conn.close()
        return stats
        
    except Exception as e:
        print(f"Error getting stats: {e}")
        return {}

def add_threat_intelligence(indicator, indicator_type, threat_type, confidence, source):
    """Add threat intelligence indicator"""
    try:
        conn = db_manager.get_connection()
        cursor = conn.cursor()
        
        if db_manager.use_postgres:
            cursor.execute('''
                INSERT INTO threat_intelligence (indicator, indicator_type, threat_type, confidence, source)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (indicator, indicator_type) DO UPDATE SET
                threat_type = EXCLUDED.threat_type,
                confidence = EXCLUDED.confidence,
                source = EXCLUDED.source
            ''', (indicator, indicator_type, threat_type, confidence, source))
        else:
            cursor.execute('''
                INSERT OR REPLACE INTO threat_intelligence 
                (indicator, indicator_type, threat_type, confidence, source)
                VALUES (?, ?, ?, ?, ?)
            ''', (indicator, indicator_type, threat_type, confidence, source))
        
        conn.commit()
        conn.close()
        
    except Exception as e:
        print(f"Error adding threat intelligence: {e}")

def check_threat_intelligence(indicator, indicator_type):
    """Check if indicator exists in threat intelligence"""
    try:
        conn = db_manager.get_connection()
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT * FROM threat_intelligence WHERE indicator = %s AND indicator_type = %s" 
            if db_manager.use_postgres else
            "SELECT * FROM threat_intelligence WHERE indicator = ? AND indicator_type = ?",
            (indicator, indicator_type)
        )
        
        result = cursor.fetchone()
        conn.close()
        
        if result:
            if db_manager.use_postgres:
                return {
                    'indicator': result[1], 'indicator_type': result[2],
                    'threat_type': result[3], 'confidence': result[4],
                    'source': result[5]
                }
            else:
                return {
                    'indicator': result['indicator'], 'indicator_type': result['indicator_type'],
                    'threat_type': result['threat_type'], 'confidence': result['confidence'],
                    'source': result['source']
                }
        return None
        
    except Exception as e:
        print(f"Error checking threat intelligence: {e}")
        return None

def clear_alerts():
    """Clear all alerts"""
    try:
        conn = db_manager.get_connection()
        cursor = conn.cursor()
        cursor.execute('DELETE FROM alerts')
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Error clearing alerts: {e}")

# Backward compatibility functions
def get_db_connection():
    return db_manager.get_connection()
