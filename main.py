
import threading
import time
from db import init_db
from network_sniffer import start_sniffer
from app import app
from ai_model import initialize_ai_model

def main():
    print("🚀 Initializing Advanced Cyberattack Detection System...")
    print("=" * 60)
    
    # Initialize database
    print("📊 Initializing database...")
    init_db()
    print("✅ Database initialized successfully.")
    
    # Initialize and train AI model
    print("🤖 Initializing AI/ML models...")
    detector = initialize_ai_model()
    if detector.is_loaded:
        print("✅ AI model loaded/trained successfully.")
    else:
        print("⚠️ AI model using simulation mode.")
    
    # Start network sniffer in background thread
    print("🔍 Starting enhanced network sniffer...")
    sniffer_thread = threading.Thread(target=start_sniffer, daemon=True)
    sniffer_thread.start()
    print("✅ Network sniffer started successfully.")
    
    print("=" * 60)
    print("🌟 SYSTEM FEATURES ENABLED:")
    print("   ✓ Real-time ML-based threat detection")
    print("   ✓ PostgreSQL database support")
    print("   ✓ SIEM integration (Splunk, ELK)")
    print("   ✓ Advanced threat correlation")
    print("   ✓ Threat intelligence feeds")
    print("   ✓ APT detection capabilities")
    print("   ✓ Smart alert correlation")
    print("   ✓ Threat hunting APIs")
    print("   ")
    print("=" * 60)
    
    # Start Flask application
    print("🌐 Starting advanced web dashboard on port 5000...")
    print("📱 Access your dashboard at: http://localhost:5000/")
    print("=" * 60)
    
    app.run(host="0.0.0.0", port=5000, debug=True)

if __name__ == "__main__":
    main()
