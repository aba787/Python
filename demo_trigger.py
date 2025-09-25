
from db import add_alert
import time
import uuid
from datetime import datetime

def sql_injection():
    print("Triggering SQL Injection scenario...")
    correlation_id = str(uuid.uuid4())
    
    add_alert("HIGH", "SQL injection detected: UNION SELECT statement in login form", 
             source_ip="192.168.1.45", protocol="HTTP", port=80, 
             confidence=0.95, threat_type="SQL Injection Attack", correlation_id=correlation_id)
    time.sleep(0.5)
    add_alert("MEDIUM", "Multiple database error responses detected", 
             source_ip="192.168.1.45", protocol="HTTP", port=80,
             confidence=0.82, threat_type="SQL Injection Attack", correlation_id=correlation_id)
    time.sleep(0.5)
    add_alert("HIGH", "Unauthorized database access attempt", 
             source_ip="192.168.1.45", protocol="TCP", port=3306,
             confidence=0.91, threat_type="SQL Injection Attack", correlation_id=correlation_id)

def syn_flood():
    print("Triggering SYN Flood scenario...")
    correlation_id = str(uuid.uuid4())
    
    for i in range(5):
        add_alert("HIGH", f"SYN flood detected: {1000 + i*200} connections per second", 
                 source_ip="10.0.0.100", destination_ip="192.168.1.10", 
                 protocol="TCP", port=80, confidence=0.98, 
                 threat_type="Denial of Service Attack", correlation_id=correlation_id)
        time.sleep(0.3)

def phishing_email():
    print("Triggering Phishing Email scenario...")
    correlation_id = str(uuid.uuid4())
    
    add_alert("MEDIUM", "Suspicious email detected with malicious attachment", 
             source_ip="mail.suspicious-domain.com", protocol="SMTP", port=25,
             confidence=0.78, threat_type="Phishing Attack", correlation_id=correlation_id)
    time.sleep(1)
    add_alert("HIGH", "Phishing link clicked by user", 
             source_ip="192.168.1.25", destination_ip="evil.phishing-site.com",
             protocol="HTTP", port=80, confidence=0.92, 
             threat_type="Phishing Attack", correlation_id=correlation_id)
    time.sleep(0.5)
    add_alert("MEDIUM", "Credential harvesting attempt detected", 
             source_ip="192.168.1.25", destination_ip="evil.phishing-site.com",
             protocol="HTTPS", port=443, confidence=0.85,
             threat_type="Phishing Attack", correlation_id=correlation_id)

def port_scan():
    print("Triggering Port Scan scenario...")
    correlation_id = str(uuid.uuid4())
    
    add_alert("MEDIUM", "Port scan detected from IP 192.168.1.100", 
             source_ip="192.168.1.100", destination_ip="10.0.0.5",
             protocol="TCP", confidence=0.88, threat_type="Network Probing/Scanning", correlation_id=correlation_id)
    time.sleep(0.5)
    add_alert("MEDIUM", "Multiple ports probed: 22, 80, 443, 3389", 
             source_ip="192.168.1.100", destination_ip="10.0.0.5",
             protocol="TCP", confidence=0.90, threat_type="Network Probing/Scanning", correlation_id=correlation_id)
    time.sleep(0.5)
    add_alert("LOW", "Network reconnaissance activity detected", 
             source_ip="192.168.1.100", destination_ip="10.0.0.0/24",
             confidence=0.75, threat_type="Network Probing/Scanning", correlation_id=correlation_id)

def malware_beacon():
    print("Triggering Malware Beacon scenario...")
    correlation_id = str(uuid.uuid4())
    
    add_alert("HIGH", "Malware beacon detected: C2 communication", 
             source_ip="192.168.1.75", destination_ip="malicious-c2.example.com",
             protocol="HTTPS", port=443, confidence=0.96,
             threat_type="Command and Control Communication", correlation_id=correlation_id)
    time.sleep(1)
    add_alert("HIGH", "Suspicious outbound traffic to known malicious IP", 
             source_ip="192.168.1.75", destination_ip="185.220.101.42",
             protocol="TCP", port=8080, confidence=0.94,
             threat_type="Command and Control Communication", correlation_id=correlation_id)
    time.sleep(0.5)
    add_alert("MEDIUM", "Encrypted payload transmission detected", 
             source_ip="192.168.1.75", destination_ip="185.220.101.42",
             protocol="TCP", port=8080, confidence=0.87,
             threat_type="Command and Control Communication", correlation_id=correlation_id)

def apt_campaign():
    print("Triggering Advanced Persistent Threat (APT) campaign...")
    correlation_id = str(uuid.uuid4())
    
    # Stage 1: Initial reconnaissance
    add_alert("MEDIUM", "APT: Initial network reconnaissance detected", 
             source_ip="external.attacker.com", destination_ip="192.168.1.0/24",
             protocol="ICMP", confidence=0.82, 
             threat_type="Advanced Persistent Threat", correlation_id=correlation_id)
    time.sleep(2)
    
    # Stage 2: Spear phishing
    add_alert("HIGH", "APT: Targeted spear phishing email with weaponized document", 
             source_ip="spoofed-sender@legitimate-domain.com", 
             destination_ip="192.168.1.30", protocol="SMTP", port=25,
             confidence=0.91, threat_type="Advanced Persistent Threat", correlation_id=correlation_id)
    time.sleep(3)
    
    # Stage 3: Initial compromise
    add_alert("HIGH", "APT: Malicious macro execution detected", 
             source_ip="192.168.1.30", protocol="FILE", 
             confidence=0.95, threat_type="Advanced Persistent Threat", correlation_id=correlation_id)
    time.sleep(2)
    
    # Stage 4: Lateral movement
    add_alert("HIGH", "APT: Lateral movement using compromised credentials", 
             source_ip="192.168.1.30", destination_ip="192.168.1.45",
             protocol="SMB", port=445, confidence=0.89,
             threat_type="Advanced Persistent Threat", correlation_id=correlation_id)
    time.sleep(3)
    
    # Stage 5: Data exfiltration
    add_alert("HIGH", "APT: Sensitive data exfiltration to external server", 
             source_ip="192.168.1.45", destination_ip="data-exfil.attacker.com",
             protocol="HTTPS", port=443, confidence=0.93,
             threat_type="Advanced Persistent Threat", correlation_id=correlation_id)

def data_exfiltration():
    print("Triggering Data Exfiltration scenario...")
    correlation_id = str(uuid.uuid4())
    
    add_alert("HIGH", "Unusual large data transfer detected", 
             source_ip="192.168.1.55", destination_ip="external-storage.com",
             protocol="HTTPS", port=443, confidence=0.88,
             threat_type="Data Exfiltration", correlation_id=correlation_id)
    time.sleep(1)
    add_alert("MEDIUM", "Database dump activity detected", 
             source_ip="192.168.1.55", destination_ip="192.168.1.200",
             protocol="TCP", port=3306, confidence=0.84,
             threat_type="Data Exfiltration", correlation_id=correlation_id)
    time.sleep(1)
    add_alert("HIGH", "Encrypted file transfer to suspicious domain", 
             source_ip="192.168.1.55", destination_ip="suspicious-cloud.com",
             protocol="HTTPS", port=443, confidence=0.92,
             threat_type="Data Exfiltration", correlation_id=correlation_id)

def insider_threat():
    print("Triggering Insider Threat scenario...")
    correlation_id = str(uuid.uuid4())
    
    add_alert("MEDIUM", "After-hours access to sensitive systems", 
             source_ip="192.168.1.80", destination_ip="192.168.1.250",
             protocol="SSH", port=22, confidence=0.79,
             threat_type="Insider Threat", correlation_id=correlation_id)
    time.sleep(2)
    add_alert("HIGH", "Unauthorized access to HR database", 
             source_ip="192.168.1.80", destination_ip="192.168.1.250",
             protocol="TCP", port=5432, confidence=0.91,
             threat_type="Insider Threat", correlation_id=correlation_id)
    time.sleep(1)
    add_alert("HIGH", "Mass file download from file server", 
             source_ip="192.168.1.80", destination_ip="192.168.1.220",
             protocol="SMB", port=445, confidence=0.87,
             threat_type="Insider Threat", correlation_id=correlation_id)

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        scenario = sys.argv[1]
        scenarios = {
            "sql_injection": sql_injection,
            "syn_flood": syn_flood,
            "phishing_email": phishing_email,
            "port_scan": port_scan,
            "malware_beacon": malware_beacon,
            "apt_campaign": apt_campaign,
            "data_exfiltration": data_exfiltration,
            "insider_threat": insider_threat
        }
        
        if scenario in scenarios:
            scenarios[scenario]()
        else:
            print(f"Unknown scenario. Available: {', '.join(scenarios.keys())}")
    else:
        print("Available scenarios:")
        for name in ["sql_injection", "syn_flood", "phishing_email", "port_scan", 
                    "malware_beacon", "apt_campaign", "data_exfiltration", "insider_threat"]:
            print(f"  - {name}")
