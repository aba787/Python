
from db import add_alert
import time

def sql_injection():
    print("Triggering SQL Injection scenario...")
    add_alert("HIGH", "SQL injection detected: UNION SELECT statement in login form")
    add_alert("MEDIUM", "Multiple database error responses detected")
    add_alert("HIGH", "Unauthorized database access attempt")

def syn_flood():
    print("Triggering SYN Flood scenario...")
    for i in range(5):
        add_alert("HIGH", f"SYN flood detected: {1000 + i*200} connections per second")
        time.sleep(0.5)

def phishing_email():
    print("Triggering Phishing Email scenario...")
    add_alert("MEDIUM", "Suspicious email detected with malicious attachment")
    add_alert("HIGH", "Phishing link clicked by user")
    add_alert("MEDIUM", "Credential harvesting attempt detected")

def port_scan():
    print("Triggering Port Scan scenario...")
    add_alert("MEDIUM", "Port scan detected from IP 192.168.1.100")
    add_alert("MEDIUM", "Multiple ports probed: 22, 80, 443, 3389")
    add_alert("LOW", "Network reconnaissance activity detected")

def malware_beacon():
    print("Triggering Malware Beacon scenario...")
    add_alert("HIGH", "Malware beacon detected: C2 communication")
    add_alert("HIGH", "Suspicious outbound traffic to known malicious IP")
    add_alert("MEDIUM", "Encrypted payload transmission detected")

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        scenario = sys.argv[1]
        if scenario == "sql_injection":
            sql_injection()
        elif scenario == "syn_flood":
            syn_flood()
        elif scenario == "phishing_email":
            phishing_email()
        elif scenario == "port_scan":
            port_scan()
        elif scenario == "malware_beacon":
            malware_beacon()
        else:
            print("Unknown scenario. Available: sql_injection, syn_flood, phishing_email, port_scan, malware_beacon")
