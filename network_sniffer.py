
import random
import time
import threading
import uuid
from datetime import datetime
from db import add_alert, check_threat_intelligence, add_threat_intelligence
from ai_model import detector

class ThreatCorrelationEngine:
    def __init__(self):
        self.correlation_rules = {
            'multiple_failed_logins': {
                'description': 'Multiple failed login attempts detected',
                'threshold': 5,
                'time_window': 300,  # 5 minutes
                'severity': 'MEDIUM'
            },
            'port_scan_detection': {
                'description': 'Port scanning activity detected',
                'threshold': 10,
                'time_window': 60,   # 1 minute
                'severity': 'MEDIUM'
            },
            'dos_attack_pattern': {
                'description': 'DoS attack pattern detected',
                'threshold': 100,
                'time_window': 30,   # 30 seconds
                'severity': 'HIGH'
            },
            'suspicious_data_exfiltration': {
                'description': 'Unusual data transfer volumes detected',
                'threshold': 3,
                'time_window': 600,  # 10 minutes
                'severity': 'HIGH'
            }
        }
        self.event_buffer = []
        self.max_buffer_size = 1000
    
    def correlate_events(self, new_event):
        """Correlate events to detect complex attack patterns"""
        self.event_buffer.append(new_event)
        
        # Keep buffer size manageable
        if len(self.event_buffer) > self.max_buffer_size:
            self.event_buffer = self.event_buffer[-self.max_buffer_size:]
        
        # Check correlation rules
        current_time = datetime.now()
        
        for rule_name, rule in self.correlation_rules.items():
            if self.check_correlation_rule(rule_name, rule, current_time):
                correlation_id = str(uuid.uuid4())
                self.trigger_correlation_alert(rule_name, rule, correlation_id)
    
    def check_correlation_rule(self, rule_name, rule, current_time):
        """Check if a correlation rule is triggered"""
        time_threshold = current_time.timestamp() - rule['time_window']
        
        if rule_name == 'multiple_failed_logins':
            failed_login_count = sum(1 for event in self.event_buffer 
                                   if event.get('type') == 'failed_login' and 
                                   event.get('timestamp', 0) > time_threshold)
            return failed_login_count >= rule['threshold']
        
        elif rule_name == 'port_scan_detection':
            port_scan_count = sum(1 for event in self.event_buffer 
                                if event.get('type') == 'port_scan' and 
                                event.get('timestamp', 0) > time_threshold)
            return port_scan_count >= rule['threshold']
        
        elif rule_name == 'dos_attack_pattern':
            dos_count = sum(1 for event in self.event_buffer 
                          if event.get('threat_type') == 'Denial of Service Attack' and 
                          event.get('timestamp', 0) > time_threshold)
            return dos_count >= rule['threshold']
        
        elif rule_name == 'suspicious_data_exfiltration':
            exfil_count = sum(1 for event in self.event_buffer 
                            if event.get('type') == 'data_exfiltration' and 
                            event.get('timestamp', 0) > time_threshold)
            return exfil_count >= rule['threshold']
        
        return False
    
    def trigger_correlation_alert(self, rule_name, rule, correlation_id):
        """Trigger a correlation-based alert"""
        message = f"CORRELATION ALERT: {rule['description']} - Rule: {rule_name}"
        add_alert(
            level=rule['severity'],
            message=message,
            correlation_id=correlation_id,
            threat_type="Correlated Attack Pattern"
        )
        print(f"🔗 Correlation Alert: {message}")

# Global correlation engine
correlation_engine = ThreatCorrelationEngine()

def load_threat_intelligence_feeds():
    """Load threat intelligence from various sources"""
    # Sample threat intelligence data
    threat_indicators = [
        ('192.168.1.100', 'ip', 'malware_c2', 90, 'Internal_Analysis'),
        ('suspicious-domain.com', 'domain', 'phishing', 85, 'Threat_Feed'),
        ('malware-hash-123', 'hash', 'malware', 95, 'Virus_Total'),
        ('10.0.0.50', 'ip', 'botnet', 80, 'Security_Vendor'),
        ('evil.example.com', 'domain', 'malware_c2', 88, 'Threat_Intel_Provider')
    ]
    
    print("Loading threat intelligence feeds...")
    for indicator, ind_type, threat_type, confidence, source in threat_indicators:
        add_threat_intelligence(indicator, ind_type, threat_type, confidence, source)
    
    print(f"Loaded {len(threat_indicators)} threat intelligence indicators")

def generate_realistic_network_event():
    """Generate realistic network events based on ML model"""
    event_types = ['normal', 'dos_simulation', 'probe_simulation', 'data_transfer', 'login_attempt']
    event_type = random.choice(event_types)
    
    current_time = datetime.now()
    
    # Generate packet data for ML analysis
    packet_data = {
        'type': event_type,
        'timestamp': current_time.timestamp(),
        'source_ip': f"192.168.1.{random.randint(1, 254)}",
        'destination_ip': f"10.0.0.{random.randint(1, 254)}",
        'protocol': random.choice(['TCP', 'UDP', 'ICMP']),
        'port': random.choice([22, 23, 25, 53, 80, 443, 993, 995, 3389, 5432])
    }
    
    # Use ML model to analyze the packet
    analysis_result = detector.analyze_network_packet(packet_data)
    
    # Check against threat intelligence
    threat_intel = check_threat_intelligence(packet_data['source_ip'], 'ip')
    if threat_intel:
        analysis_result['risk_level'] = 'HIGH'
        analysis_result['threat_type'] = f"Known Threat: {threat_intel['threat_type']}"
        analysis_result['message'] = f"Traffic from known malicious IP: {packet_data['source_ip']}"
    
    # Generate appropriate message based on analysis
    if analysis_result['prediction'] != 'normal':
        threat_messages = {
            'dos': f"DoS attack detected from {packet_data['source_ip']} targeting {packet_data['destination_ip']}:{packet_data['port']}",
            'probe': f"Network scan detected from {packet_data['source_ip']} probing {packet_data['destination_ip']}:{packet_data['port']}",
            'r2l': f"Remote access attempt detected from {packet_data['source_ip']} to {packet_data['destination_ip']}:{packet_data['port']}",
            'u2r': f"Privilege escalation attempt detected from {packet_data['source_ip']}",
            'unknown': f"Anomalous network activity detected from {packet_data['source_ip']}"
        }
        
        message = threat_messages.get(analysis_result['prediction'], 
                                    f"Suspicious activity detected: {analysis_result['threat_type']}")
        
        # Add enhanced alert with ML analysis data
        add_alert(
            level=analysis_result['risk_level'],
            message=message,
            source_ip=packet_data['source_ip'],
            destination_ip=packet_data['destination_ip'],
            protocol=packet_data['protocol'],
            port=packet_data['port'],
            confidence=analysis_result['confidence'],
            threat_type=analysis_result['threat_type'],
            anomaly_score=analysis_result.get('anomaly_score', 0)
        )
        
        # Add to correlation engine
        correlation_event = {
            'type': analysis_result['prediction'],
            'threat_type': analysis_result['threat_type'],
            'source_ip': packet_data['source_ip'],
            'timestamp': current_time.timestamp(),
            'severity': analysis_result['risk_level']
        }
        correlation_engine.correlate_events(correlation_event)
        
    else:
        # Generate normal events occasionally for context
        if random.random() < 0.1:  # 10% chance
            normal_messages = [
                f"Normal HTTP request from {packet_data['source_ip']} to {packet_data['destination_ip']}",
                f"Successful authentication from {packet_data['source_ip']}",
                f"File transfer completed between {packet_data['source_ip']} and {packet_data['destination_ip']}",
                f"Database query executed from {packet_data['source_ip']}"
            ]
            
            message = random.choice(normal_messages)
            add_alert(
                level="INFO",
                message=message,
                source_ip=packet_data['source_ip'],
                destination_ip=packet_data['destination_ip'],
                protocol=packet_data['protocol'],
                port=packet_data['port'],
                confidence=analysis_result['confidence'],
                threat_type="Normal Traffic"
            )

def generate_advanced_attack_scenarios():
    """Generate advanced attack scenarios for testing"""
    scenarios = [
        {
            'name': 'Advanced Persistent Threat (APT)',
            'events': [
                ('Initial reconnaissance', 'MEDIUM', 'probe'),
                ('Spear phishing email', 'HIGH', 'r2l'),
                ('Lateral movement', 'HIGH', 'u2r'),
                ('Data exfiltration', 'HIGH', 'data_exfiltration')
            ]
        },
        {
            'name': 'Multi-stage Malware Campaign',
            'events': [
                ('Malware dropper execution', 'HIGH', 'malware'),
                ('Command and control beacon', 'HIGH', 'c2_communication'),
                ('Privilege escalation', 'HIGH', 'u2r'),
                ('Credential harvesting', 'MEDIUM', 'credential_theft')
            ]
        }
    ]
    
    # Randomly trigger advanced scenarios
    if random.random() < 0.05:  # 5% chance
        scenario = random.choice(scenarios)
        correlation_id = str(uuid.uuid4())
        
        for event_desc, severity, event_type in scenario['events']:
            add_alert(
                level=severity,
                message=f"APT Campaign - {event_desc}",
                threat_type=f"Advanced Threat: {event_type}",
                correlation_id=correlation_id
            )
            time.sleep(0.5)  # Small delay between related events

def sniffer_loop():
    """Main network sniffer loop with ML integration"""
    print("🔍 Enhanced AI-powered network sniffer started...")
    
    # Load threat intelligence
    load_threat_intelligence_feeds()
    
    while True:
        try:
            # Generate realistic network event
            generate_realistic_network_event()
            
            # Occasionally generate advanced attack scenarios
            generate_advanced_attack_scenarios()
            
            # Wait before next analysis
            time.sleep(random.uniform(2, 6))
            
        except Exception as e:
            print(f"Error in sniffer loop: {e}")
            time.sleep(5)

def start_sniffer():
    """Start the enhanced network sniffer"""
    print("🚀 Starting Enhanced AI Network Sniffer...")
    sniffer_loop()
