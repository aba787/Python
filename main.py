
import threading
import time
from db import init_db
from network_sniffer import start_sniffer
from app import app

def main():
    print("Initializing Cyberattack Detection System...")
    
    # Initialize database
    init_db()
    print("Database initialized.")
    
    # Start network sniffer in background thread
    sniffer_thread = threading.Thread(target=start_sniffer, daemon=True)
    sniffer_thread.start()
    print("Network sniffer started.")
    
    # Start Flask application
    print("Starting web dashboard on port 5000...")
    app.run(host="0.0.0.0", port=5000, debug=True)

if __name__ == "__main__":
    main()
