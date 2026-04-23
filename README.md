# 🛡️ ML Cyber Attack Prediction System

## 🌟 Project Overview

The **ML Cyber Attack Prediction System** is a comprehensive, local solution for real-time network traffic analysis and cyber attack detection using machine learning. This system combines Random Forest classification with live deep packet inspection to provide robust network security monitoring, immediate threat prediction, and audible alerting capabilities.

![System Architecture](new_architecture.png)

### 🎯 Key Features

- **Real-time Network Monitoring**: Captures and analyzes live network traffic flows via a Scapy-based monitoring agent.
- **Machine Learning Detection**: Uses a trained **Random Forest** model on KDD-style metrics to classify benign vs. malicious traffic.
- **Intelligent Payload Decoding**: Unpacks URL-encodings to run Deep Packet Inspection (DPI) signatures against SQL Injection, Path Traversal, and Brute Force attacks.
- **Web Dashboard**: Modern **Next.js** glassmorphism interface for visualizing threats.
- **Geographical Threat Map**: Real-time **Leaflet.js** global map visualizing attacker IP origins using `ip-api.com` with pulsating severity markers.
- **Active Alerting**: Triggers real-time visual toast notifications and **audible alarms** via the Web Audio API on attack detection.

---

## 📁 Project Structure

```text
CyberAttackPrediction/
├── target_website/
│   └── app.py                  # Vulnerable Flask demo web application (port 5000)
│
├── ml_service/
│   ├── ml_ec2_service.py       # Flask REST API serving Random Forest predictions (port 8080)
│   ├── train_rf_model.py       # Script to train and export the Random Forest model
│   ├── config.py               # Central configuration for ML service thresholds and ports
│   ├── requirements.txt        # Python dependencies for the ML backend
│   └── rf_artifacts/           # Directory storing compiled model binaries
│       ├── rf_model.pkl        # The trained Random Forest classifier
│       ├── scaler.pkl          # Feature standard scaler for data normalization
│       └── label_encoder.pkl   # Label encoder for KDD categorical metrics
│
├── monitor_app/
│   ├── package.json            # Node.js dependencies and run scripts
│   ├── app/                    # Next.js Source Directory
│   │   ├── layout.tsx          # Root HTML layout (includes Leaflet.js CDN)
│   │   ├── page.tsx            # Main React UI, Threat Map, and Audio Alarm system
│   │   ├── globals.css         # Tailwind directives and custom map/pulse animations
│   │   └── api/                
│   │       ├── predictionStore.ts   # Shared in-memory state for tracking predictions globally
│   │       ├── predictions/route.ts # Endpoint receiving live threats from Network Agent
│   │       ├── geo/route.ts         # Endpoint for resolving IP geolocation
│   │       └── ml-status/route.ts   # Endpoint proxying health checks to the ML Service
│   └── network_agent/          
│       ├── network_monitor_agent.py # Scapy-based Python sniffer (forces UTF-8), DPI Engine, API dispatcher
│       └── requirements.txt         # Python dependencies for the packet agent
│
├── simulate_attack.py          # Primary test script to launch DDoS, SQLi, Brute Force against target
├── send_test_attacks.py        # Lightweight alternative script for isolated attack testing
├── test_attacks_clean.py       # Refined scripting for clean traffic flow simulations
├── IDS.ipynb                   # Jupyter notebook containing full training, evaluation, and pipeline logic
├── kdd_train.csv               # Standard NSL-KDD dataset used for training the Random Forest
├── kdd_test.csv                # Standard NSL-KDD testing suite for model validation
├── new_architecture.png        # Latest visual architecture and workflow diagram
└── README.md                   # This comprehensive documentation file
```

---

## 🔄 System Workflow

```text
[Target Website :5000]  ←── normal/attack traffic ───  [simulate_attack.py]
         │
         ▼
[network_agent (Scapy)] ── packet capture + DPI heuristic feature extraction
         │
         ▼  HTTP POST
[ML Service :8080]  ── StandardScaler → Random Forest predict → return threat %
         │
         ▼
[Monitor App :3000]  ── display live tracking, play alarm, push toast notifications
```

---

## 🌐 Target Website (`target_website/app.py`)

A simple Flask web app running on **port 5000** that acts as the traffic target for the IDS to monitor.
```bash
cd target_website
pip install flask
python app.py
```

Browse to `http://localhost:5000` to generate normal traffic. Available API endpoints:
- `GET /api/users`
- `GET /api/products`
- `GET /api/transactions`
- `GET /api/health`
- `GET /api/search?q=<query>`
- `GET /api/login`

---

## 🚨 Attack Simulator (`simulate_attack.py`)

Generates 6 categories of attack traffic against `localhost:5000`:
```bash
python simulate_attack.py              # Run all attacks
python simulate_attack.py --type flood       # HTTP flood (DDoS-like)
python simulate_attack.py --type bruteforce  # Login brute force
python simulate_attack.py --type sqli        # SQL injection probing
python simulate_attack.py --type scan        # Port scan
python simulate_attack.py --type burst       # Rapid TCP burst
python simulate_attack.py --type slowloris   # Slow connection drain
```

---

## ⚙️ ML Service (`ml_service/`)

Flask REST API serving predictions on **port 8080**.

### Setup
```bash
cd ml_service
pip install -r requirements.txt
```

### Train models (Optional)
```bash
python train_rf_model.py       # Trains Random Forest from kdd_train.csv
```

### Run prediction server
```bash
python ml_ec2_service.py
```

---

## 🖥️ Monitor App (`monitor_app/`)

A **Next.js** dashboard that visualizes live predictions from the ML service and handles alarm states.

```bash
cd monitor_app
npm install
npm run dev        # http://localhost:3000
```
> **Note:** Once the dashboard opens, you must click anywhere on the interface at least once to authorize your browser to play the audio alerting system during an attack.

### Run Network Agent
In a separate terminal, to start snapping packets to evaluate:
```bash
python monitor_app/network_agent/network_monitor_agent.py
```

---

## 🛠️ Requirements
```text
Python 3.8+
Flask
scikit-learn
pandas, numpy
scapy (for network_agent)
joblib
Node.js 18+ (for Dashboard)
```

## 🔐 Security Considerations

- The traffic simulator `simulate_attack.py` generates suspicious payloads designed to test intrusion detection metrics.
- This project is for security learning, traffic analytics, and controlled testing only.
- Run attack simulation only in your own local/lab environment against authorized `localhost` targets.
- Do not use these scripts against unauthorized systems.
