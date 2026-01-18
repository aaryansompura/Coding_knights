# 🛡️ SENTINEL - Healthcare Cyber-Resilience Platform

A real-time **AI-powered Security Operations Center (SOC)** designed to protect healthcare infrastructure from cyber threats. Built with a **5-layer hybrid detection architecture** combining rule-based detection, machine learning (Autoencoder), and graph-based correlation.

![Python](https://img.shields.io/badge/Python-3.10+-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-green)
![PyTorch](https://img.shields.io/badge/PyTorch-2.0+-red)

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   Layer 5: Dashboard                     │
│        Real-time visualization & threat monitoring       │
├─────────────────────────────────────────────────────────┤
│                Layer 4: Risk Rate Fusion                 │
│     0.4×Rules + 0.4×Autoencoder + 0.2×Graph = Risk      │
├────────────────┬─────────────────┬──────────────────────┤
│ Layer 1: Rules │ Layer 2: AI    │ Layer 3: Graph       │
│ Deterministic  │ Autoencoder    │ Correlation          │
│ Pattern Match  │ Anomaly Detect │ Relationship Map     │
└────────────────┴─────────────────┴──────────────────────┘
```

---

## ⚡ Features

### 🔍 Multi-Layer Threat Detection
| Layer | Technology | Detects |
|-------|------------|---------|
| **L1 Rules** | Regex + Thresholds | SQL Injection, XSS, BOLA, DDoS |
| **L2 AI** | PyTorch Autoencoder | Zero-day anomalies, unknown patterns |
| **L3 Graph** | Network Analysis | Coordinated attacks, attacker relationships |

### 🎯 Attack Types Detected
- 🔓 **BOLA** - Broken Object Level Authorization
- 🌊 **DDoS** - Distributed Denial of Service
- 🔑 **Brute Force** - Credential Stuffing
- 💉 **SQL Injection** - Database Attacks
- 🔗 **XSS** - Cross-Site Scripting
- 🕷️ **Data Scraping** - Automated Harvesting
- 📤 **Data Exfiltration** - Data Breach Attempts

### 📊 Real-Time Dashboard
- **Risk Rate Gauge** - Combined threat level (0-100%)
- **Traffic Normality** - AI-based pattern health
- **Live Alert Feed** - Real-time threat notifications
- **Network Graph** - Visual threat map with IP connections

---

## 🚀 Quick Start

### Prerequisites
- Python 3.10+
- pip

### Installation

```bash
# Clone the repository
git clone <repo-url>
cd healthcare-security-platform/backend

# Create virtual environment
python -m venv venv
venv\Scripts\activate  # Windows
# source venv/bin/activate  # Linux/Mac

# Install dependencies
pip install -r requirements.txt

# Train the AI model
python train_anomaly_model.py
```

### Running

```bash
# Start the server
.\start.bat
# OR
uvicorn app.main:app --reload

# In another terminal, start attack simulation
.\simulate.bat
# OR
python -m simulator.traffic
```

### Access Dashboard
Open: **http://127.0.0.1:8000**

---

## 📁 Project Structure

```
backend/
├── app/
│   ├── main.py              # FastAPI app + Autoencoder integration
│   ├── api/
│   │   └── routes.py        # Protected patient API endpoints
│   ├── sentinel/
│   │   ├── detection.py     # Layer 1: Rule-based detection
│   │   ├── graphs.py        # Layer 3: Graph correlation
│   │   ├── engine.py        # Alert processing loop
│   │   └── ingest.py        # Request logging
│   └── static/
│       ├── index.html       # Main dashboard
│       ├── threat-map.html  # Network graph visualization
│       ├── css/style.css    # Dashboard styling
│       └── js/dashboard.js  # Frontend logic
├── simulator/
│   └── traffic.py           # Multi-attack traffic generator
├── rules.py                 # Top 10 cyber attack rules 
├── train_anomaly_model.py   # Autoencoder training script
├── start.bat                # Server launcher
└── simulate.bat             # Attack simulator launcher
```

---

## 🧠 How It Works

### Risk Rate Calculation
```
Risk Rate = (0.4 × Rules Risk) + (0.4 × AI Risk) + (0.2 × Graph Risk)
```

| Risk Level | Score | Status |
|------------|-------|--------|
| 🟢 LOW | < 30% | System Secure |
| 🟡 MEDIUM | 30-70% | Elevated Activity |
| 🔴 HIGH | > 70% | Active Threat |

### Traffic Normality (AI)
```
Normality = 99% - (reconstruction_error × 24%)
```
- **95%+**: Traffic is very normal
- **75-95%**: Slightly unusual patterns
- **<75%**: Anomaly detected

---

## 🛠️ API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Dashboard UI |
| GET | `/api/v1/dashboard/stats` | Risk rate, layer scores |
| GET | `/api/v1/dashboard/alerts` | Active threat alerts |
| GET | `/api/v1/dashboard/graph` | Network visualization data |
| GET | `/api/v1/patients` | Patient list (protected) |
| GET | `/api/v1/patients/{id}` | Patient details |
| POST | `/antigravity/check` | Manual anomaly check |

---

## 🧪 Testing Rules Engine

```bash
python rules.py
```

This runs diagnostics for all 10 attack detection rules.

---

## 📜 License

MIT License - Built for healthcare security research and education.

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Submit a pull request

---

**Built with ❤️ for Healthcare Security**



<img width="352" height="887" alt="image" src="https://github.com/user-attachments/assets/d7206dd5-ba72-419a-a7db-880c9581f0f9" />
<img width="359" height="847" alt="image" src="https://github.com/user-attachments/assets/6ed57da4-4bec-40e2-998f-01127daf712a" />
This type of structure should be there


