
from flask import Flask, render_template, jsonify, request
from db import get_alerts, get_stats, add_alert, clear_alerts, check_threat_intelligence, add_threat_intelligence
import demo_trigger
import json
import requests
from datetime import datetime, timedelta
import os

app = Flask(__name__)

# SIEM Integration Configuration
SPLUNK_HOST = os.getenv('SPLUNK_HOST', 'localhost')
SPLUNK_PORT = os.getenv('SPLUNK_PORT', '8089')
SPLUNK_USERNAME = os.getenv('SPLUNK_USERNAME', 'admin')
SPLUNK_PASSWORD = os.getenv('SPLUNK_PASSWORD', 'password')

ELK_HOST = os.getenv('ELK_HOST', 'localhost')
ELK_PORT = os.getenv('ELK_PORT', '9200')

class SIEMIntegration:
    @staticmethod
    def send_to_splunk(alert_data):
        """Send alert to Splunk"""
        try:
            splunk_url = f"https://{SPLUNK_HOST}:{SPLUNK_PORT}/services/receivers/simple"
            headers = {'Content-Type': 'application/json'}
            
            # Format data for Splunk
            splunk_event = {
                'time': alert_data.get('timestamp', datetime.now().isoformat()),
                'source': 'cyberattack_detection_system',
                'sourcetype': 'security_alert',
                'event': alert_data
            }
            
            response = requests.post(
                splunk_url,
                headers=headers,
                json=splunk_event,
                auth=(SPLUNK_USERNAME, SPLUNK_PASSWORD),
                verify=False,
                timeout=10
            )
            
            if response.status_code == 200:
                print(f"✅ Alert sent to Splunk: {alert_data['message'][:50]}...")
            else:
                print(f"❌ Failed to send to Splunk: {response.status_code}")
                
        except Exception as e:
            print(f"Error sending to Splunk: {e}")
    
    @staticmethod
    def send_to_elasticsearch(alert_data):
        """Send alert to Elasticsearch"""
        try:
            elk_url = f"http://{ELK_HOST}:{ELK_PORT}/security-alerts/_doc"
            headers = {'Content-Type': 'application/json'}
            
            # Add timestamp for Elasticsearch
            alert_data['@timestamp'] = alert_data.get('timestamp', datetime.now().isoformat())
            
            response = requests.post(
                elk_url,
                headers=headers,
                json=alert_data,
                timeout=10
            )
            
            if response.status_code in [200, 201]:
                print(f"✅ Alert sent to Elasticsearch: {alert_data['message'][:50]}...")
            else:
                print(f"❌ Failed to send to Elasticsearch: {response.status_code}")
                
        except Exception as e:
            print(f"Error sending to Elasticsearch: {e}")

siem_integration = SIEMIntegration()

@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE')
    response.headers.add('Cache-Control', 'no-cache')
    return response

@app.route('/')
def dashboard():
    return render_template('index.html')

@app.route('/arabic')
def arabic_dashboard():
    """Arabic language dashboard with RTL support"""
    return render_template('arabic.html')

@app.route('/api/alerts')
def api_alerts():
    try:
        # Get query parameters for filtering
        level = request.args.get('level')
        start_time = request.args.get('start_time')
        end_time = request.args.get('end_time')
        limit = request.args.get('limit', 100, type=int)
        
        filters = {}
        if level:
            filters['level'] = level
        if start_time:
            filters['start_time'] = start_time
        if end_time:
            filters['end_time'] = end_time
        
        alerts = get_alerts(limit=limit, filters=filters if filters else None)
        print(f"API returning {len(alerts)} alerts")
        return jsonify(alerts)
    except Exception as e:
        print(f"Error in api_alerts: {e}")
        return jsonify([]), 500

@app.route('/api/stats')
def api_stats():
    try:
        stats = get_stats()
        print(f"API returning stats: {stats}")
        return jsonify(stats)
    except Exception as e:
        print(f"Error in api_stats: {e}")
        return jsonify({}), 500

@app.route('/api/threat-intelligence', methods=['GET', 'POST'])
def api_threat_intelligence():
    if request.method == 'POST':
        try:
            data = request.get_json()
            add_threat_intelligence(
                data['indicator'],
                data['indicator_type'],
                data['threat_type'],
                data['confidence'],
                data['source']
            )
            return jsonify({'success': True, 'message': 'Threat intelligence added'})
        except Exception as e:
            return jsonify({'error': str(e)}), 400
    
    else:
        indicator = request.args.get('indicator')
        indicator_type = request.args.get('type')
        
        if indicator and indicator_type:
            result = check_threat_intelligence(indicator, indicator_type)
            return jsonify(result if result else {})
        else:
            return jsonify({'error': 'indicator and type parameters required'}), 400

@app.route('/api/threat-hunting/search', methods=['POST'])
def api_threat_hunting_search():
    """Advanced threat hunting search"""
    try:
        data = request.get_json()
        query = data.get('query', '')
        time_range = data.get('time_range', '24h')
        
        # Convert time range to datetime
        if time_range == '1h':
            start_time = datetime.now() - timedelta(hours=1)
        elif time_range == '24h':
            start_time = datetime.now() - timedelta(days=1)
        elif time_range == '7d':
            start_time = datetime.now() - timedelta(days=7)
        else:
            start_time = datetime.now() - timedelta(days=1)
        
        # Search alerts based on query
        filters = {'start_time': start_time.isoformat()}
        
        # Add query-based filtering
        if 'level:' in query:
            level = query.split('level:')[1].split()[0].upper()
            if level in ['HIGH', 'MEDIUM', 'LOW', 'INFO']:
                filters['level'] = level
        
        alerts = get_alerts(limit=1000, filters=filters)
        
        # Further filter based on query text
        if query and not query.startswith('level:'):
            filtered_alerts = []
            for alert in alerts:
                if (query.lower() in alert['message'].lower() or 
                    (alert['threat_type'] and query.lower() in alert['threat_type'].lower()) or
                    (alert['source_ip'] and query in alert['source_ip'])):
                    filtered_alerts.append(alert)
            alerts = filtered_alerts
        
        return jsonify({
            'results': alerts,
            'total': len(alerts),
            'query': query,
            'time_range': time_range
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/threat-hunting/patterns', methods=['GET'])
def api_threat_hunting_patterns():
    """Get threat patterns and IOCs"""
    try:
        # Analyze recent alerts for patterns
        alerts = get_alerts(limit=500)
        
        patterns = {
            'top_source_ips': {},
            'top_threat_types': {},
            'attack_timelines': [],
            'correlation_groups': {}
        }
        
        # Analyze source IPs
        for alert in alerts:
            if alert['source_ip']:
                ip = alert['source_ip']
                patterns['top_source_ips'][ip] = patterns['top_source_ips'].get(ip, 0) + 1
        
        # Analyze threat types
        for alert in alerts:
            if alert['threat_type']:
                threat = alert['threat_type']
                patterns['top_threat_types'][threat] = patterns['top_threat_types'].get(threat, 0) + 1
        
        # Sort by frequency
        patterns['top_source_ips'] = dict(sorted(patterns['top_source_ips'].items(), 
                                                key=lambda x: x[1], reverse=True)[:10])
        patterns['top_threat_types'] = dict(sorted(patterns['top_threat_types'].items(), 
                                                  key=lambda x: x[1], reverse=True)[:10])
        
        # Group by correlation ID
        for alert in alerts:
            if alert['correlation_id']:
                corr_id = alert['correlation_id']
                if corr_id not in patterns['correlation_groups']:
                    patterns['correlation_groups'][corr_id] = []
                patterns['correlation_groups'][corr_id].append(alert)
        
        return jsonify(patterns)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/trigger', methods=['POST'])
def api_trigger():
    data = request.get_json()
    scenario = data.get('scenario', '')
    
    if scenario == 'sql_injection':
        demo_trigger.sql_injection()
    elif scenario == 'syn_flood':
        demo_trigger.syn_flood()
    elif scenario == 'phishing_email':
        demo_trigger.phishing_email()
    elif scenario == 'port_scan':
        demo_trigger.port_scan()
    elif scenario == 'malware_beacon':
        demo_trigger.malware_beacon()
    elif scenario == 'apt_campaign':
        demo_trigger.apt_campaign()
    elif scenario == 'data_exfiltration':
        demo_trigger.data_exfiltration()
    else:
        return jsonify({'error': 'Unknown scenario'}), 400
    
    return jsonify({'success': True, 'message': f'Triggered {scenario} scenario'})

@app.route('/api/clear', methods=['POST'])
def api_clear():
    clear_alerts()
    return jsonify({'success': True, 'message': 'Alerts cleared'})

@app.route('/api/siem/send', methods=['POST'])
def api_siem_send():
    """Manually send alerts to SIEM systems"""
    try:
        data = request.get_json()
        alert_id = data.get('alert_id')
        systems = data.get('systems', ['splunk', 'elk'])
        
        if alert_id:
            alerts = get_alerts(limit=1, filters={'id': alert_id})
            if alerts:
                alert = alerts[0]
                
                if 'splunk' in systems:
                    siem_integration.send_to_splunk(alert)
                
                if 'elk' in systems:
                    siem_integration.send_to_elasticsearch(alert)
                
                return jsonify({'success': True, 'message': 'Alert sent to SIEM systems'})
        
        return jsonify({'error': 'Alert not found'}), 404
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Auto-send high severity alerts to SIEM
def auto_send_to_siem(alert_data):
    """Automatically send high-severity alerts to SIEM systems"""
    if alert_data.get('level') in ['HIGH', 'CRITICAL']:
        try:
            siem_integration.send_to_splunk(alert_data)
            siem_integration.send_to_elasticsearch(alert_data)
        except Exception as e:
            print(f"Error auto-sending to SIEM: {e}")

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, debug=True)
