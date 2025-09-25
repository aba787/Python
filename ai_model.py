
import random
import joblib
import numpy as np

class CyberAttackDetector:
    def __init__(self):
        # Simulate a lightweight ML model for demo purposes
        self.model = None
        self.is_loaded = False
    
    def load_model(self, model_path="model.pkl"):
        """Load ML model from file"""
        try:
            self.model = joblib.load(model_path)
            self.is_loaded = True
            print(f"Model loaded successfully from {model_path}")
        except FileNotFoundError:
            print(f"Model file {model_path} not found. Using simulation mode.")
            self.is_loaded = False
    
    def predict(self, features):
        """Predict if network traffic is normal or attack"""
        if self.is_loaded and self.model:
            # Use actual ML model
            prediction = self.model.predict([features])
            confidence = self.model.predict_proba([features]).max()
            return prediction[0], confidence
        else:
            # Simulate prediction for demo
            is_attack = random.choice([True, False])
            confidence = random.uniform(0.7, 0.95)
            return "Attack" if is_attack else "Normal", confidence
    
    def analyze_network_packet(self, packet_data):
        """Analyze network packet and return threat assessment"""
        # Simulate feature extraction from packet
        features = [
            random.uniform(0, 1),  # Packet size normalized
            random.uniform(0, 1),  # Protocol type
            random.uniform(0, 1),  # Connection duration
            random.uniform(0, 1),  # Bytes sent
            random.uniform(0, 1)   # Bytes received
        ]
        
        prediction, confidence = self.predict(features)
        
        return {
            "prediction": prediction,
            "confidence": round(confidence, 3),
            "features": features,
            "risk_level": self.get_risk_level(prediction, confidence)
        }
    
    def get_risk_level(self, prediction, confidence):
        """Convert prediction to risk level"""
        if prediction == "Attack":
            if confidence > 0.9:
                return "HIGH"
            elif confidence > 0.7:
                return "MEDIUM"
            else:
                return "LOW"
        else:
            return "INFO"

# Global detector instance
detector = CyberAttackDetector()

def initialize_ai_model():
    """Initialize the AI model"""
    detector.load_model()
    return detector
