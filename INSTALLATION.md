
# 🚀 Installation Guide

## System Requirements

### Minimum Requirements
- **Operating System**: Linux/Unix (Ubuntu 20.04+ recommended)
- **Python**: 3.11 or higher
- **RAM**: 2GB minimum, 4GB recommended
- **Storage**: 1GB free space
- **Network**: Internet connection for package installation

### Recommended Environment
- **Replit**: Cloud-based development environment (recommended)
- **Local Linux**: Ubuntu/Debian/CentOS
- **WSL2**: Windows Subsystem for Linux

## Quick Installation (Replit - Recommended)

### 1. Import to Replit
1. Go to [Replit.com](https://replit.com)
2. Click "Create Repl"
3. Select "Import from GitHub"
4. Enter: `https://github.com/aba787/Python`
5. Click "Import from GitHub"

### 2. Run the System
```bash
# The system will auto-install dependencies
python main.py
```

## Local Installation

### 1. Clone Repository
```bash
git clone https://github.com/aba787/Python.git
cd Python
```

### 2. Create Virtual Environment (Optional)
```bash
python3 -m venv cyber_security_env
source cyber_security_env/bin/activate  # Linux/Mac
# or
cyber_security_env\Scripts\activate     # Windows
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Install System Dependencies (Linux)
```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install python3-dev libpcap-dev

# CentOS/RHEL
sudo yum install python3-devel libpcap-devel

# Arch Linux
sudo pacman -S python libpcap
```

### 5. Run the System
```bash
python main.py
```

## Docker Installation (Advanced)

### 1. Create Dockerfile
```dockerfile
FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .
EXPOSE 5000

CMD ["python", "main.py"]
```

### 2. Build and Run
```bash
docker build -t cyber-security-ai .
docker run -p 5000:5000 cyber-security-ai
```

## Verification

### 1. Check System Status
```bash
# Test main dashboard
curl http://localhost:5000

# Test vulnerable app
python vulnerable_app.py &
curl http://localhost:8080

# Test attack simulator
python attack_simulator.py
```

### 2. Access Web Interfaces
- **Main Dashboard**: `http://localhost:5000`
- **Vulnerable App**: `http://localhost:8080`
- **Demo Dashboard**: `http://localhost:5000/demo`

## Troubleshooting

### Common Issues

#### 1. Permission Denied for Network Monitoring
```bash
# Solution: Run with appropriate permissions or use simulation mode
sudo python main.py
# or use the built-in simulation mode (automatic in Replit)
```

#### 2. Port Already in Use
```bash
# Check what's using the port
netstat -tulpn | grep :5000

# Kill the process or change port in code
```

#### 3. Missing Dependencies
```bash
# Reinstall requirements
pip install --upgrade -r requirements.txt

# Install specific packages
pip install scapy flask plotly scikit-learn
```

#### 4. Database Issues
```bash
# Remove and recreate database
rm alerts.db
python -c "from db import create_database; create_database()"
```

### Performance Optimization

#### 1. Memory Usage
```python
# Reduce model complexity in ai_model.py
n_estimators=100  # instead of 200
max_depth=5       # instead of 10
```

#### 2. CPU Usage
```python
# Reduce monitoring frequency in network_sniffer.py
time.sleep(1)     # instead of 0.1
```

## Development Setup

### 1. Development Dependencies
```bash
pip install pytest black flake8 mypy
```

### 2. Code Formatting
```bash
black *.py
flake8 *.py
```

### 3. Testing
```bash
pytest tests/
```

## Production Deployment

### 1. Environment Variables
```bash
export FLASK_ENV=production
export FLASK_DEBUG=False
```

### 2. WSGI Server
```bash
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 dashboard:app
```

### 3. Reverse Proxy (Nginx)
```nginx
server {
    listen 80;
    server_name your-domain.com;
    
    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

## Support

If you encounter any issues:

1. **Check the logs** in the console output
2. **Verify dependencies** are correctly installed
3. **Check system requirements** are met
4. **Open an issue** on GitHub with error details

For more help, visit: [GitHub Issues](https://github.com/aba787/Python/issues)
