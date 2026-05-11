# 🛸 Drone Security Assessment Tool

An AI-powered desktop application for assessing the security posture of drones using
network scanning, rule-based risk scoring, and a trained Machine Learning classifier
informed by the ISOT Drone Dataset.

---

## 📌 Overview

This tool analyzes drone networks by scanning open ports, detecting protocols,
evaluating Wi-Fi security, and running safe connectivity tests. It produces a
risk score (0–100) and generates a detailed PDF security report.

The ML model is a Random Forest classifier trained on 3,000 synthetic drone
scenarios, achieving **97.17% accuracy** on the test set.

---

## ✨ Features

- 🔍 **Live Drone Scan** — port scanning, protocol detection, Wi-Fi analysis
- 🎲 **Random Fake Drone** — generates random drone scenarios for testing without a real drone
- 📊 **Risk Scoring** — ISOT-informed rule-based engine (0–100 scale)
- 🤖 **ML Classification** — Random Forest: Normal / Suspicious / Attack
- 🛡️ **Vulnerability Findings** — severity-rated findings with recommendations
- ⚔️ **Likely Attack Vectors** — ranked ISOT attack categories (DoS, MITM, Replay, etc.)
- 📄 **PDF Report** — professional security report with score card, findings, and AI analysis
- 🧠 **AI Explanation** — Ollama-powered natural language explanation of results

---

## 🧠 ML Model Performance

| Class | Precision | Recall | F1-Score |
|---|---|---|---|
| Attack | 0.9474 | 0.9391 | 0.9432 |
| Normal | 0.9946 | 0.9840 | 0.9892 |
| Suspicious | 0.9668 | 0.9765 | 0.9716 |
| **Overall Accuracy** | | | **97.17%** |

> Trained on 3,000 synthetic drone scenarios generated from the ISOT Drone Dataset feature space.

---

## 🗂️ Project Structure
drone_security_tool/
├── ai/ # Vulnerability engine + AI explainer
├── gui/ # PyQt5 main window
├── ml/ # ML model, training scripts, inference
├── reports/ # PDF report generator
├── scanner/ # Port scanner, Wi-Fi scanner, protocol detector
├── tests/ # Safe connectivity tests
└── utils/ # Helpers and logger


---

## ⚙️ Installation

**Requirements:** Python 3.9+

bash
git clone https://github.com/Abdulrahman3987/drone-security-tool.git
cd drone-security-tool
pip install -r requirements.txt

🚀 Usage
cd drone_security_tool
python main.py

📡 Supported Drone Protocols & Ports
Port	Usage
8889	Tello Command
14550	MAVLink GCS
8890 / 8891	Telemetry / Video
11111	Tello Video Stream
4090	DJI Control
8888	AP Interface
⚠️ Disclaimer
This tool is intended for authorized security research and educational purposes only.
Do not use it against drones or networks you do not own or have explicit permission to test.

👤 Author
M23 Graduation project members 
- Mohammed Bodi
- Abdulrahman Al-Odhaib
- Yazeed Al-Abdullatif
- Abdullah Al-Muammar
