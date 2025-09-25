
import random
import time
import threading
from db import add_alert

def generate_normal_event():
    normal_events = [
        ("INFO", "Normal HTTP request processed"),
        ("INFO", "User login successful"),
        ("INFO", "File transfer completed"),
        ("LOW", "High bandwidth usage detected"),
        ("LOW", "Multiple failed login attempts")
    ]
    return random.choice(normal_events)

def generate_attack_event():
    attack_events = [
        ("HIGH", "SQL injection attempt detected"),
        ("HIGH", "DDoS attack in progress"),
        ("MEDIUM", "Suspicious port scan detected"),
        ("HIGH", "Malware signature found"),
        ("MEDIUM", "Brute force attack detected"),
        ("HIGH", "Data exfiltration attempt"),
        ("MEDIUM", "Unauthorized access attempt"),
        ("HIGH", "Cross-site scripting (XSS) detected")
    ]
    return random.choice(attack_events)

def sniffer_loop():
    while True:
        # 30% chance of attack event, 70% normal
        if random.random() < 0.3:
            level, message = generate_attack_event()
        else:
            level, message = generate_normal_event()
        
        add_alert(level, message)
        
        # Wait 3-7 seconds before next event
        time.sleep(random.uniform(3, 7))

def start_sniffer():
    print("Network sniffer simulator started...")
    sniffer_loop()
