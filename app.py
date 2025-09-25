
from flask import Flask, render_template, jsonify, request
from db import get_alerts, get_stats, add_alert, clear_alerts
import demo_trigger

app = Flask(__name__)

@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE')
    return response

@app.route('/')
def dashboard():
    return render_template('index.html')

@app.route('/arabic')
def arabic_dashboard():
    return render_template('arabic.html')

@app.route('/api/alerts')
def api_alerts():
    try:
        alerts = get_alerts()
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
    else:
        return jsonify({'error': 'Unknown scenario'}), 400
    
    return jsonify({'success': True, 'message': f'Triggered {scenario} scenario'})

@app.route('/api/clear', methods=['POST'])
def api_clear():
    clear_alerts()
    return jsonify({'success': True, 'message': 'Alerts cleared'})

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, debug=True)
