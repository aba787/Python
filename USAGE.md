
# 📚 Usage Guide

## System Components

The Cyber Security AI Detection System consists of three main components:

1. **Main Detection System** (`main.py`)
2. **Vulnerable Application** (`vulnerable_app.py`)
3. **Attack Simulator** (`attack_simulator.py`)

## 🎯 Main Detection System

### Starting the System
```bash
python main.py
```

### Dashboard Access
- **URL**: `http://localhost:5000`
- **Features**: Real-time monitoring, statistics, alerts

### Dashboard Sections

#### 1. Real-time Statistics
- **Total Threats**: Number of detected attacks
- **Active Connections**: Current network connections
- **System Status**: AI model status and health

#### 2. Attack Type Distribution
- **Pie Chart**: Shows percentage of each attack type
- **Types**: DoS, Port Scan, SQL Injection, XSS, DNS, Brute Force, Malware

#### 3. Geographic Threat Map
- **World Map**: Shows attack sources by country
- **Hover Info**: Attack count and threat level

#### 4. Confidence Levels
- **High Confidence**: > 80% certainty
- **Medium Confidence**: 60-80% certainty
- **Low Confidence**: < 60% certainty

#### 5. Alerts Table
- **Real-time Updates**: Live alert feed
- **Details**: Timestamp, type, confidence, message
- **Filtering**: By threat level and time

## 🎯 Vulnerable Application

### Purpose
Educational tool demonstrating common web vulnerabilities for testing the detection system.

### Starting the Vulnerable App
```bash
python vulnerable_app.py
```

### Access
- **URL**: `http://localhost:8080`
- **Note**: Contains intentional security flaws

### Available Vulnerabilities

#### 1. SQL Injection
**Location**: Search functionality
**Example Payloads**:
```sql
' UNION SELECT username,password,email,role FROM users--
' OR '1'='1
admin'; DROP TABLE users;--
```

**Test Steps**:
1. Go to search form
2. Enter SQL injection payload
3. Observe the executed SQL query
4. Check main dashboard for detection alerts

#### 2. Directory Traversal
**Location**: File viewer
**Example Payloads**:
```
../../../etc/passwd
..\..\..\..\windows\win.ini
../../../../proc/version
```

**Test Steps**:
1. Go to file viewer form
2. Enter directory traversal payload
3. Observe file contents
4. Check for detection alerts

#### 3. Cross-Site Scripting (XSS)
**Location**: Comment section
**Example Payloads**:
```javascript
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
javascript:alert('XSS')
```

#### 4. Authentication Bypass
**Location**: Admin panel
**Example**:
- Direct access to `/admin` without authentication
- Weak session management

## 🎯 Attack Simulator

### Purpose
Generates realistic attack traffic to test and demonstrate the AI detection system.

### Starting the Simulator
```bash
python attack_simulator.py
```

### Attack Scenarios

#### 1. SQL Injection Attacks
```bash
# Automatic SQL injection simulation
# Targets: /search endpoint
# Payloads: Various SQL injection techniques
```

#### 2. DoS/DDoS Attacks
```bash
# High-frequency request simulation
# Rate: 100+ requests per second
# Target: Main application endpoints
```

#### 3. Port Scanning
```bash
# Sequential port access simulation
# Range: Common ports (22, 80, 443, etc.)
# Pattern: Rapid port enumeration
```

#### 4. Brute Force Attacks
```bash
# Login attempt simulation
# Targets: /login endpoint
# Method: Dictionary-based password attempts
```

#### 5. Directory Traversal
```bash
# File system access attempts
# Payloads: Path traversal patterns
# Target: /file endpoint
```

## 📊 Monitoring and Analysis

### Real-time Monitoring
1. **Open Dashboard**: `http://localhost:5000`
2. **Watch Alerts**: Real-time alert feed
3. **Monitor Statistics**: Live charts and graphs
4. **Analyze Patterns**: Geographic and temporal analysis

### Alert Analysis
```javascript
// Example alert structure
{
  "id": 1,
  "timestamp": "2024-01-15 10:30:45",
  "threat_level": "HIGH",
  "attack_type": "SQL Injection",
  "confidence": 0.95,
  "source_ip": "192.168.1.100",
  "message": "Detected SQL injection attempt in search query"
}
```

### Statistical Analysis
- **Attack Frequency**: Attacks per hour/day
- **Success Rate**: Detection accuracy
- **False Positives**: Incorrect classifications
- **Response Time**: Detection latency

## 🔧 Configuration

### AI Model Settings
```python
# In ai_model.py
n_estimators = 200        # Number of trees in forest
max_depth = 10           # Maximum tree depth
class_weight = 'balanced' # Handle imbalanced data
```

### Detection Thresholds
```python
# Confidence thresholds
HIGH_CONFIDENCE = 0.8    # 80%+
MEDIUM_CONFIDENCE = 0.6  # 60-80%
LOW_CONFIDENCE = 0.4     # 40-60%
```

### Network Monitoring
```python
# Packet capture settings
CAPTURE_COUNT = 200      # Packets per session
INTERFACE = 'eth0'       # Network interface
PROMISCUOUS = True       # Promiscuous mode
```

## 📈 Performance Tuning

### Memory Optimization
```python
# Reduce model size
n_estimators = 100       # Instead of 200
max_depth = 5           # Instead of 10
```

### CPU Optimization
```python
# Reduce monitoring frequency
time.sleep(1)           # Instead of 0.1 seconds
```

### Database Optimization
```sql
-- Index for faster queries
CREATE INDEX idx_timestamp ON alerts(timestamp);
CREATE INDEX idx_threat_level ON alerts(threat_level);
```

## 🚨 Alert Management

### Alert Levels
- **HIGH**: Immediate action required
- **MEDIUM**: Investigation needed
- **LOW**: Monitoring recommended

### Response Procedures
1. **High Alerts**: Block IP, investigate immediately
2. **Medium Alerts**: Monitor closely, analyze patterns
3. **Low Alerts**: Log for trend analysis

### Alert Suppression
```python
# Suppress duplicate alerts
SUPPRESS_DURATION = 300  # 5 minutes
MAX_ALERTS_PER_IP = 10   # Per hour
```

## 📝 Logging

### Log Levels
```python
import logging
logging.basicConfig(level=logging.INFO)

# Available levels:
# DEBUG, INFO, WARNING, ERROR, CRITICAL
```

### Log Files
- **Application**: `app.log`
- **Attacks**: `attacks.log`
- **Errors**: `errors.log`

## 🔍 Troubleshooting

### Common Issues

#### 1. No Alerts Generated
```bash
# Check if vulnerable app is running
curl http://localhost:8080

# Check if simulator is active
python attack_simulator.py
```

#### 2. Low Detection Accuracy
```python
# Retrain the model
from ai_model import train_model
train_model()
```

#### 3. High False Positives
```python
# Adjust confidence thresholds
CONFIDENCE_THRESHOLD = 0.9  # Increase threshold
```

#### 4. Performance Issues
```bash
# Monitor system resources
top
htop
iostat
```

## 📊 Reporting

### Generate Reports
```python
# Weekly attack summary
python -c "
from db import get_alerts
alerts = get_alerts(days=7)
print(f'Total alerts: {len(alerts)}')
"
```

### Export Data
```python
# Export to CSV
import pandas as pd
from db import get_alerts

alerts = get_alerts()
df = pd.DataFrame(alerts)
df.to_csv('security_report.csv', index=False)
```

## 🎓 Educational Use

### Classroom Demonstration
1. **Setup**: Run all three components
2. **Explain**: AI detection principles
3. **Demonstrate**: Live attack detection
4. **Analyze**: Results and patterns

### Learning Objectives
- Understanding cyber attack patterns
- AI/ML in cybersecurity
- Real-time threat detection
- Security monitoring best practices

For more detailed information, visit the [GitHub repository](https://github.com/aba787/Python).
