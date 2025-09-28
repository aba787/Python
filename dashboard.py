
from flask import Flask, render_template, jsonify, request
from db import get_db, init_db
import threading
import random
import time
from collections import defaultdict
import re
import sqlite3
from datetime import datetime, timedelta

app = Flask(__name__)
init_db()

# Global simulation state
simulation_running = False
background_generator_running = False

def extract_attack_info(message):
    """Extract attack type, confidence, and source IP from alert message"""
    attack_type = "Unknown"
    confidence = 0.0
    source_ip = "N/A"
    threat_level = "MEDIUM"
    
    # Extract attack type
    type_match = re.search(r'Type: ([^|]+)', message)
    if type_match:
        attack_type = type_match.group(1).strip()
    
    # Extract confidence
    conf_match = re.search(r'Confidence: ([\d.]+)', message)
    if conf_match:
        confidence = float(conf_match.group(1))
    
    # Extract source IP
    ip_match = re.search(r'Source: ([\d.]+)', message)
    if ip_match:
        source_ip = ip_match.group(1)
    
    # Determine threat level based on attack type and confidence
    if attack_type in ['SQL Injection', 'XSS Attack', 'DoS/DDoS'] and confidence > 0.8:
        threat_level = "HIGH"
    elif confidence > 0.6:
        threat_level = "MEDIUM"
    else:
        threat_level = "LOW"
    
    return attack_type, confidence, source_ip, threat_level

def add_demo_alert(attack_type, message, threat_level="MEDIUM", source_ip=None):
    """Add demonstration alert to database"""
    if source_ip is None:
        source_ip = f"192.168.1.{random.randint(100, 254)}"
    
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        enhanced_message = f"{message} | Type: {attack_type} | Confidence: {random.uniform(0.7, 0.95):.2f} | Source: {source_ip} | Level: {threat_level}"
        
        cursor.execute("INSERT INTO alerts (message) VALUES (?)", (enhanced_message,))
        conn.commit()
        conn.close()
        print(f"✅ Demo alert added: {attack_type} - {threat_level}")
    except Exception as e:
        print(f"Error adding demo alert: {e}")

def background_alert_generator():
    """Generate random background alerts for demonstration"""
    global background_generator_running
    
    attack_scenarios = [
        ("Normal", "Normal network activity detected", "LOW"),
        ("Port Scan", "Suspicious port scanning activity detected", "MEDIUM"),
        ("Brute Force", "Multiple failed login attempts detected", "MEDIUM"),
        ("Malware/Trojan", "Suspicious outbound connection detected", "HIGH"),
        ("DNS Attack", "Unusual DNS query patterns detected", "MEDIUM")
    ]
    
    while background_generator_running:
        try:
            attack_type, message, level = random.choice(attack_scenarios)
            add_demo_alert(attack_type, message, level)
            time.sleep(random.uniform(5, 15))  # Random interval between alerts
        except Exception as e:
            print(f"Background generator error: {e}")
            time.sleep(5)

@app.route('/')
def dashboard():
    return render_template('demo_dashboard.html')

@app.route('/alerts')
def get_alerts():
    """Get recent alerts with enhanced information"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT id, message, timestamp FROM alerts ORDER BY timestamp DESC LIMIT 50")
        raw_alerts = cursor.fetchall()
        conn.close()
        
        alerts = []
        for alert in raw_alerts:
            attack_type, confidence, source_ip, threat_level = extract_attack_info(alert[1])
            alerts.append({
                'id': alert[0],
                'message': alert[1].split(' | ')[0],  # Clean message
                'timestamp': alert[2],
                'attack_type': attack_type,
                'threat_level': threat_level,
                'confidence': confidence,
                'source_ip': source_ip
            })
        
        return jsonify(alerts)
    except Exception as e:
        return jsonify([])

@app.route('/stats')
def get_stats():
    """Get attack statistics for the last 5 minutes"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        # Get alerts from last 5 minutes
        five_minutes_ago = datetime.now() - timedelta(minutes=5)
        cursor.execute("SELECT message FROM alerts WHERE timestamp > ?", (five_minutes_ago,))
        recent_alerts = cursor.fetchall()
        conn.close()
        
        # Count by attack type and threat level
        attack_counts = defaultdict(int)
        threat_counts = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        
        for alert in recent_alerts:
            attack_type, confidence, source_ip, threat_level = extract_attack_info(alert[0])
            attack_counts[attack_type] += 1
            threat_counts[threat_level] += 1
        
        return jsonify({
            'attack_types': dict(attack_counts),
            'threat_levels': threat_counts,
            'total_alerts': len(recent_alerts)
        })
    except Exception as e:
        return jsonify({'attack_types': {}, 'threat_levels': {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}, 'total_alerts': 0})

@app.route('/scenario/<scenario_type>', methods=['POST'])
def run_scenario(scenario_type):
    """Run specific attack scenario for demonstration"""
    scenarios = {
        'sqli': {
            'name': 'SQL Injection',
            'alerts': [
                "SQL injection payload detected: ' OR '1'='1",
                "Malicious SQL keywords found in user input",
                "Database manipulation attempt blocked",
                "Union-based SQL injection detected"
            ]
        },
        'syn_flood': {
            'name': 'SYN Flood',
            'alerts': [
                "High volume of SYN packets detected",
                "Possible SYN flood attack in progress",
                "Connection rate exceeded normal thresholds",
                "DoS attack pattern identified"
            ]
        },
        'phishing': {
            'name': 'Phishing',
            'alerts': [
                "Suspicious email pattern detected",
                "Potential phishing attempt identified",
                "Malicious URL in communication",
                "Social engineering attack detected"
            ]
        },
        'port_scan': {
            'name': 'Port Scan',
            'alerts': [
                "Port scanning activity detected",
                "Multiple port connection attempts",
                "Network reconnaissance behavior",
                "Stealth scan pattern identified"
            ]
        },
        'malware': {
            'name': 'Malware/Trojan',
            'alerts': [
                "Malware beacon activity detected",
                "Suspicious outbound connection",
                "Command and control communication",
                "Trojan behavior pattern identified"
            ]
        }
    }
    
    if scenario_type not in scenarios:
        return jsonify({'success': False, 'message': 'Invalid scenario'})
    
    scenario = scenarios[scenario_type]
    
    # Generate 3-5 alerts for this scenario
    num_alerts = random.randint(3, 5)
    for i in range(num_alerts):
        message = random.choice(scenario['alerts'])
        threat_level = 'HIGH' if scenario_type in ['sqli', 'syn_flood'] else 'MEDIUM'
        add_demo_alert(scenario['name'], message, threat_level)
        time.sleep(0.5)  # Small delay between alerts
    
    return jsonify({'success': True, 'message': f'{scenario["name"]} scenario executed'})

@app.route('/background_generator', methods=['POST'])
def toggle_background_generator():
    """Toggle background alert generator"""
    global background_generator_running
    
    action = request.json.get('action', 'start')
    
    if action == 'start' and not background_generator_running:
        background_generator_running = True
        thread = threading.Thread(target=background_alert_generator, daemon=True)
        thread.start()
        return jsonify({'success': True, 'message': 'Background generator started'})
    elif action == 'stop':
        background_generator_running = False
        return jsonify({'success': True, 'message': 'Background generator stopped'})
    else:
        return jsonify({'success': False, 'message': 'Generator already running or invalid action'})

@app.route('/alert_details/<int:alert_id>')
def get_alert_details(alert_id):
    """Get detailed information about a specific alert"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,))
        alert = cursor.fetchone()
        conn.close()
        
        if alert:
            attack_type, confidence, source_ip, threat_level = extract_attack_info(alert[1])
            return jsonify({
                'id': alert[0],
                'full_message': alert[1],
                'timestamp': alert[2],
                'attack_type': attack_type,
                'threat_level': threat_level,
                'confidence': confidence,
                'source_ip': source_ip,
                'details': {
                    'description': f'Detailed analysis of {attack_type} attack',
                    'recommendation': 'Block source IP and review security policies',
                    'false_positive_likelihood': random.choice(['Low', 'Medium', 'High'])
                }
            })
        else:
            return jsonify({'error': 'Alert not found'})
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/clear_alerts', methods=['POST'])
def clear_alerts():
    """Clear all alerts for demonstration reset"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM alerts")
        conn.commit()
        conn.close()
        return jsonify({'success': True, 'message': 'All alerts cleared'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

def run_dashboard():
    print("🌐 Starting demonstration dashboard on http://0.0.0.0:5000")
    app.run(host="0.0.0.0", port=5000, debug=False, use_reloader=False)

if __name__ == "__main__":
    run_dashboard()
