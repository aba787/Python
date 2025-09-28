
import sys
import time
import threading
from network_sniffer import start_sniffing
from dashboard import run_dashboard

def main():
    print("🚀 Starting Cyber Security AI Detection System...")
    print("=" * 50)
    
    try:
        # Initialize AI model
        print("🤖 Loading AI model...")
        
        # Start network monitoring in background
        print("📡 Initializing network monitoring...")
        start_sniffing()
        
        # Give network monitor time to start
        time.sleep(2)
        
        print("🌐 Starting web dashboard...")
        print("📊 Dashboard will be available at: http://0.0.0.0:5000")
        print("=" * 50)
        
        # Start web dashboard (this will block)
        run_dashboard()
        
    except KeyboardInterrupt:
        print("\n⏹️  Shutting down system...")
        sys.exit(0)
    except Exception as e:
        print(f"❌ Error starting system: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
