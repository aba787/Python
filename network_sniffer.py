
import threading
import time
import random
import math
from collections import defaultdict, deque
from ai_model import AdvancedCyberSecurityModel
from db import get_db

# Try to import scapy, fallback gracefully if not available
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    print("Warning: Scapy not available. Network monitoring will use simulation mode.")
    SCAPY_AVAILABLE = False

# Global variables for session tracking
session_tracker = defaultdict(lambda: {
    'start_time': time.time(),
    'packet_count': 0,
    'total_size': 0,
    'ports': set(),
    'protocols': set()
})

connection_tracker = defaultdict(int)
recent_packets = deque(maxlen=1000)

# Initialize advanced model
ai_model = AdvancedCyberSecurityModel()
ai_model.load_advanced_model()

def add_alert(message, attack_type="Unknown", confidence=0.0, source_ip="N/A"):
    """Add enhanced alert to database"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        # Enhanced alert message with more details
        enhanced_message = f"{message} | Type: {attack_type} | Confidence: {confidence:.2f} | Source: {source_ip}"
        
        cursor.execute("INSERT INTO alerts (message) VALUES (?)", (enhanced_message,))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Error adding alert to database: {e}")

def calculate_entropy(data):
    """Calculate Shannon entropy of payload data"""
    if not data or len(data) == 0:
        return 0
    
    # Count byte frequencies
    freq = defaultdict(int)
    for byte in data:
        freq[byte] += 1
    
    # Calculate entropy
    entropy = 0
    length = len(data)
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    
    return entropy

def analyze_protocol(packet):
    """Advanced protocol analysis"""
    protocol_info = {
        'type': 'Unknown',
        'port': 0,
        'suspicious_indicators': []
    }
    
    if not SCAPY_AVAILABLE:
        # Simulation mode protocol assignment
        protocols = ['TCP', 'UDP', 'HTTP', 'HTTPS', 'DNS', 'ICMP']
        protocol_info['type'] = random.choice(protocols)
        protocol_info['port'] = random.choice([21, 22, 23, 25, 53, 80, 443, 993, 995, 8080])
        return protocol_info
    
    try:
        if packet.haslayer(TCP):
            protocol_info['type'] = 'TCP'
            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                protocol_info['port'] = tcp_layer.dport
                
                # Detect HTTP/HTTPS
                if tcp_layer.dport == 80:
                    protocol_info['type'] = 'HTTP'
                elif tcp_layer.dport == 443:
                    protocol_info['type'] = 'HTTPS'
                elif tcp_layer.dport == 22:
                    protocol_info['type'] = 'SSH'
                elif tcp_layer.dport == 21:
                    protocol_info['type'] = 'FTP'
                
                # Check for suspicious TCP flags
                if tcp_layer.flags & 0x01:  # FIN flag
                    if tcp_layer.flags & 0x02:  # SYN flag
                        protocol_info['suspicious_indicators'].append('FIN+SYN flags')
                
                # Check for unusual port combinations
                if tcp_layer.dport > 49152:  # Dynamic port range
                    protocol_info['suspicious_indicators'].append('High port number')
        
        elif packet.haslayer(UDP):
            protocol_info['type'] = 'UDP'
            if packet.haslayer(UDP):
                udp_layer = packet[UDP]
                protocol_info['port'] = udp_layer.dport
                
                if udp_layer.dport == 53:
                    protocol_info['type'] = 'DNS'
        
        elif packet.haslayer(ICMP):
            protocol_info['type'] = 'ICMP'
            protocol_info['port'] = 0
        
        # Check for DNS tunneling indicators
        if packet.haslayer(DNS) and packet.haslayer(Raw):
            dns_layer = packet[DNS]
            if hasattr(dns_layer, 'qd') and dns_layer.qd:
                query_name = str(dns_layer.qd.qname)
                if len(query_name) > 50:  # Unusually long DNS query
                    protocol_info['suspicious_indicators'].append('Long DNS query')
    
    except Exception as e:
        print(f"Protocol analysis error: {e}")
    
    return protocol_info

def extract_advanced_features(packet, protocol_info):
    """Extract advanced features for ML analysis"""
    try:
        current_time = time.time()
        
        if SCAPY_AVAILABLE and packet.haslayer(IP):
            src_ip = packet[IP].src
            packet_size = len(packet)
            
            # Update session tracking
            session_key = src_ip
            session = session_tracker[session_key]
            session['packet_count'] += 1
            session['total_size'] += packet_size
            session['ports'].add(protocol_info['port'])
            session['protocols'].add(protocol_info['type'])
            
            # Calculate session duration
            session_duration = current_time - session['start_time']
            
            # Update connection tracking
            connection_tracker[src_ip] += 1
            
            # Track recent packets for frequency analysis
            recent_packets.append(current_time)
            
            # Calculate packet frequency (packets per second in last 60 seconds)
            recent_time = current_time - 60
            recent_count = sum(1 for t in recent_packets if t > recent_time)
            packet_frequency = recent_count
            
            # Calculate payload entropy
            payload_entropy = 0
            if packet.haslayer(Raw):
                payload_data = bytes(packet[Raw])
                payload_entropy = calculate_entropy(payload_data)
            
            # Map protocol to numeric value
            protocol_map = {
                'TCP': 0, 'UDP': 1, 'ICMP': 2, 'HTTP': 3,
                'HTTPS': 4, 'DNS': 5, 'SSH': 6, 'FTP': 7
            }
            protocol_num = protocol_map.get(protocol_info['type'], 0)
            
        else:
            # Simulation mode with realistic patterns
            src_ip = f"192.168.1.{random.randint(1, 254)}"
            packet_size = random.randint(64, 1500)
            session_duration = random.uniform(0.1, 300)
            packet_frequency = random.randint(1, 500)
            payload_entropy = random.uniform(0, 8)
            protocol_num = random.randint(0, 7)
            
            # Update connection tracking for simulation
            connection_tracker[src_ip] += 1
        
        # Get connection count
        connection_count = connection_tracker.get(src_ip, 1)
        
        # Create feature vector
        features = ai_model.create_advanced_features(
            packet_size, protocol_num, protocol_info['port'],
            session_duration, packet_frequency, payload_entropy, connection_count
        )
        
        return features, src_ip
        
    except Exception as e:
        print(f"Feature extraction error: {e}")
        return None, "Unknown"

def process_advanced_packet(packet):
    """Advanced packet processing with AI analysis"""
    try:
        # Analyze protocol
        protocol_info = analyze_protocol(packet)
        
        # Extract features
        features, src_ip = extract_advanced_features(packet, protocol_info)
        
        if features:
            # AI prediction
            attack_id, attack_type, confidence = ai_model.predict_attack_type(features)
            
            # Generate alert message
            if attack_id == 0:  # Normal
                message = f"✅ Normal traffic detected"
                print(f"[INFO] {message} - Protocol: {protocol_info['type']}, Source: {src_ip}")
                add_alert(message, attack_type, confidence, src_ip)
            else:  # Attack detected
                suspicious_details = ""
                if protocol_info['suspicious_indicators']:
                    suspicious_details = f" | Indicators: {', '.join(protocol_info['suspicious_indicators'])}"
                
                message = f"🚨 {attack_type} detected! Protocol: {protocol_info['type']}, Port: {protocol_info['port']}{suspicious_details}"
                print(f"[ALERT] {message} - Source: {src_ip}, Confidence: {confidence:.2f}")
                add_alert(message, attack_type, confidence, src_ip)
                
                # Additional logging for high-confidence attacks
                if confidence > 0.8:
                    print(f"[HIGH CONFIDENCE ALERT] {attack_type} from {src_ip} with {confidence:.2f} confidence")
        
    except Exception as e:
        print(f"Error processing packet: {e}")

def simulate_advanced_traffic():
    """Simulate realistic network traffic with various attack patterns"""
    attack_scenarios = [
        ('Normal Web Traffic', 0.6, lambda: (random.randint(200, 800), 'HTTP', 80)),
        ('DoS Attack', 0.1, lambda: (random.randint(1000, 2000), 'TCP', 80)),
        ('Port Scan', 0.08, lambda: (64, 'TCP', random.randint(1, 65535))),
        ('SQL Injection', 0.05, lambda: (random.randint(600, 1200), 'HTTP', 80)),
        ('DNS Attack', 0.07, lambda: (random.randint(100, 300), 'DNS', 53)),
        ('SSH Brute Force', 0.06, lambda: (random.randint(100, 200), 'SSH', 22)),
        ('Malware Traffic', 0.04, lambda: (random.randint(300, 800), 'HTTPS', 443)),
    ]
    
    while True:
        try:
            # Choose scenario based on probability
            scenario_choice = random.random()
            cumulative_prob = 0
            
            for scenario_name, prob, generator in attack_scenarios:
                cumulative_prob += prob
                if scenario_choice <= cumulative_prob:
                    packet_size, protocol_type, port = generator()
                    
                    # Create simulated protocol info
                    protocol_info = {
                        'type': protocol_type,
                        'port': port,
                        'suspicious_indicators': []
                    }
                    
                    # Add suspicious indicators for certain scenarios
                    if scenario_name == 'Port Scan':
                        protocol_info['suspicious_indicators'].append('Sequential port access')
                    elif scenario_name == 'DoS Attack':
                        protocol_info['suspicious_indicators'].append('High frequency requests')
                    
                    # Create mock packet for processing
                    class MockPacket:
                        def __init__(self, size):
                            self.size = size
                        def haslayer(self, layer):
                            return False
                        def __len__(self):
                            return self.size
                    
                    mock_packet = MockPacket(packet_size)
                    process_advanced_packet(mock_packet)
                    break
            
            # Variable sleep time based on scenario
            sleep_time = random.uniform(2, 8)
            time.sleep(sleep_time)
            
        except Exception as e:
            print(f"Error in advanced simulation: {e}")
            time.sleep(5)

def start_sniffing():
    """Start advanced network monitoring"""
    print("🔍 Starting advanced network monitoring with AI...")
    
    try:
        if SCAPY_AVAILABLE:
            print("📡 Attempting real network monitoring...")
            try:
                sniff_thread = threading.Thread(
                    target=lambda: sniff(prn=process_advanced_packet, store=False, count=200),
                    daemon=True
                )
                sniff_thread.start()
                time.sleep(1)
                print("📡 Real network monitoring started successfully")
            except Exception as sniff_error:
                print(f"⚠️  Real network monitoring failed: {sniff_error}")
                print("🎭 Falling back to advanced simulation mode")
                sim_thread = threading.Thread(target=simulate_advanced_traffic, daemon=True)
                sim_thread.start()
        else:
            print("🎭 Running in advanced simulation mode")
            sim_thread = threading.Thread(target=simulate_advanced_traffic, daemon=True)
            sim_thread.start()
            
    except Exception as e:
        print(f"Could not start network monitoring: {e}")
        print("🎭 Falling back to advanced simulation mode")
        sim_thread = threading.Thread(target=simulate_advanced_traffic, daemon=True)
        sim_thread.start()
