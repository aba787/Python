
import joblib
import os
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
import pickle

class AdvancedCyberSecurityModel:
    def __init__(self):
        self.model = None
        self.scaler = StandardScaler()
        self.attack_types = {
            0: 'Normal',
            1: 'DoS/DDoS',
            2: 'Port Scan',
            3: 'SQL Injection',
            4: 'XSS Attack',
            5: 'DNS Attack',
            6: 'Brute Force',
            7: 'Malware/Trojan'
        }
        
    def create_advanced_features(self, packet_size, protocol, port, session_duration, 
                                packet_frequency, payload_entropy, connection_count):
        """Create advanced feature vector for ML model"""
        features = [
            packet_size,
            protocol,  # 0=TCP, 1=UDP, 2=ICMP, 3=HTTP, 4=HTTPS, 5=DNS
            port,
            session_duration,
            packet_frequency,
            payload_entropy,
            connection_count,
            1 if port in [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995] else 0,  # common ports
            1 if packet_size > 1000 else 0,  # large packet flag
            1 if packet_frequency > 100 else 0,  # high frequency flag
        ]
        return features
    
    def train_advanced_model(self):
        """Train model with synthetic advanced cyber security data"""
        np.random.seed(42)
        
        # Generate synthetic training data with realistic cyber attack patterns
        X = []
        y = []
        
        # Normal traffic patterns
        for _ in range(1000):
            packet_size = np.random.normal(300, 100)
            protocol = np.random.choice([0, 1], p=[0.8, 0.2])  # Mostly TCP
            port = np.random.choice([80, 443, 22, 25, 53], p=[0.4, 0.3, 0.1, 0.1, 0.1])
            session_duration = np.random.normal(30, 10)
            packet_frequency = np.random.normal(10, 5)
            payload_entropy = np.random.normal(4, 1)
            connection_count = np.random.poisson(5)
            
            features = self.create_advanced_features(
                packet_size, protocol, port, session_duration,
                packet_frequency, payload_entropy, connection_count
            )
            X.append(features)
            y.append(0)  # Normal
        
        # DoS/DDoS attacks - high frequency, large packets
        for _ in range(200):
            packet_size = np.random.normal(1200, 200)
            protocol = 0  # TCP
            port = 80
            session_duration = np.random.normal(1, 0.5)
            packet_frequency = np.random.normal(500, 100)
            payload_entropy = np.random.normal(2, 0.5)
            connection_count = np.random.poisson(100)
            
            features = self.create_advanced_features(
                packet_size, protocol, port, session_duration,
                packet_frequency, payload_entropy, connection_count
            )
            X.append(features)
            y.append(1)  # DoS/DDoS
        
        # Port Scan - multiple ports, small packets
        for _ in range(150):
            packet_size = np.random.normal(64, 20)
            protocol = 0  # TCP
            port = np.random.randint(1, 65535)
            session_duration = np.random.normal(0.1, 0.05)
            packet_frequency = np.random.normal(200, 50)
            payload_entropy = np.random.normal(1, 0.3)
            connection_count = np.random.poisson(50)
            
            features = self.create_advanced_features(
                packet_size, protocol, port, session_duration,
                packet_frequency, payload_entropy, connection_count
            )
            X.append(features)
            y.append(2)  # Port Scan
        
        # SQL Injection - HTTP traffic with suspicious patterns
        for _ in range(100):
            packet_size = np.random.normal(800, 150)
            protocol = 3  # HTTP
            port = 80
            session_duration = np.random.normal(5, 2)
            packet_frequency = np.random.normal(15, 5)
            payload_entropy = np.random.normal(6, 1)
            connection_count = np.random.poisson(3)
            
            features = self.create_advanced_features(
                packet_size, protocol, port, session_duration,
                packet_frequency, payload_entropy, connection_count
            )
            X.append(features)
            y.append(3)  # SQL Injection
        
        # XSS Attack - similar to SQL injection but different patterns
        for _ in range(80):
            packet_size = np.random.normal(600, 100)
            protocol = 3  # HTTP
            port = 80
            session_duration = np.random.normal(3, 1)
            packet_frequency = np.random.normal(20, 8)
            payload_entropy = np.random.normal(5.5, 0.8)
            connection_count = np.random.poisson(2)
            
            features = self.create_advanced_features(
                packet_size, protocol, port, session_duration,
                packet_frequency, payload_entropy, connection_count
            )
            X.append(features)
            y.append(4)  # XSS Attack
        
        # DNS Attack - DNS protocol anomalies
        for _ in range(120):
            packet_size = np.random.normal(200, 50)
            protocol = 5  # DNS
            port = 53
            session_duration = np.random.normal(0.5, 0.2)
            packet_frequency = np.random.normal(300, 100)
            payload_entropy = np.random.normal(3, 0.8)
            connection_count = np.random.poisson(20)
            
            features = self.create_advanced_features(
                packet_size, protocol, port, session_duration,
                packet_frequency, payload_entropy, connection_count
            )
            X.append(features)
            y.append(5)  # DNS Attack
        
        # Brute Force - repeated login attempts
        for _ in range(100):
            packet_size = np.random.normal(150, 30)
            protocol = 0  # TCP
            port = np.random.choice([22, 21, 23])
            session_duration = np.random.normal(2, 0.5)
            packet_frequency = np.random.normal(50, 15)
            payload_entropy = np.random.normal(2.5, 0.5)
            connection_count = np.random.poisson(30)
            
            features = self.create_advanced_features(
                packet_size, protocol, port, session_duration,
                packet_frequency, payload_entropy, connection_count
            )
            X.append(features)
            y.append(6)  # Brute Force
        
        # Malware/Trojan - irregular patterns
        for _ in range(90):
            packet_size = np.random.normal(400, 200)
            protocol = np.random.choice([0, 1])
            port = np.random.choice([443, 8080, 4444, 1337])
            session_duration = np.random.normal(60, 20)
            packet_frequency = np.random.normal(25, 10)
            payload_entropy = np.random.normal(7, 1)
            connection_count = np.random.poisson(8)
            
            features = self.create_advanced_features(
                packet_size, protocol, port, session_duration,
                packet_frequency, payload_entropy, connection_count
            )
            X.append(features)
            y.append(7)  # Malware/Trojan
        
        X = np.array(X)
        y = np.array(y)
        
        # Normalize features
        X_scaled = self.scaler.fit_transform(X)
        
        # Train Random Forest model
        self.model = RandomForestClassifier(
            n_estimators=200,
            max_depth=10,
            random_state=42,
            class_weight='balanced'
        )
        
        self.model.fit(X_scaled, y)
        
        # Save model and scaler
        with open('advanced_model.pkl', 'wb') as f:
            pickle.dump({'model': self.model, 'scaler': self.scaler}, f)
        
        print("✅ Advanced AI model trained successfully!")
        return self.model
    
    def load_advanced_model(self):
        """Load the trained advanced model"""
        if os.path.exists('advanced_model.pkl'):
            with open('advanced_model.pkl', 'rb') as f:
                data = pickle.load(f)
                self.model = data['model']
                self.scaler = data['scaler']
            return self.model
        else:
            print("🤖 Training new advanced AI model...")
            return self.train_advanced_model()
    
    def predict_attack_type(self, features):
        """Predict attack type from features"""
        if self.model is None:
            self.load_advanced_model()
        
        features_scaled = self.scaler.transform([features])
        prediction = self.model.predict(features_scaled)[0]
        confidence = max(self.model.predict_proba(features_scaled)[0])
        
        return prediction, self.attack_types[prediction], confidence

# Legacy functions for compatibility
def load_model():
    """Load the advanced cyber security model"""
    model = AdvancedCyberSecurityModel()
    model.load_advanced_model()
    return model

def train_model():
    """Train the advanced cyber security model"""
    model = AdvancedCyberSecurityModel()
    model.train_advanced_model()
    return model
