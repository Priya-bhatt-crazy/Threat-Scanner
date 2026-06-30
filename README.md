# 🛡️ SentinelX EDR

> **AI-Powered Endpoint Detection & Response (EDR) System for Real-Time Threat Detection, Intelligent Analysis, and Automated Incident Response**

![Python](https://img.shields.io/badge/Python-3.11-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-Backend-green)
![React](https://img.shields.io/badge/React-Frontend-61DAFB)
![Vite](https://img.shields.io/badge/Vite-Build-purple)
![SQLite](https://img.shields.io/badge/SQLite-Database-blue)
![JWT](https://img.shields.io/badge/JWT-Authentication-orange)
![AI](https://img.shields.io/badge/AI-Scikit--Learn-red)
![License](https://img.shields.io/badge/License-MIT-yellow)

---

# 📖 Overview

**SentinelX EDR** is an AI-powered Endpoint Detection and Response (EDR) platform developed for the **OSF Hackathon**. The system continuously monitors endpoint activities, intelligently detects malicious behavior using AI-driven threat analysis, validates threats through external threat intelligence, and automatically responds to high-risk incidents.

Unlike traditional antivirus software that primarily relies on signature-based detection, SentinelX adopts a behavioral analysis approach by monitoring endpoint activities in real time and assigning dynamic threat scores for proactive threat detection and mitigation.

---

# 🎯 Objectives

- Continuously monitor endpoint activities in real time.
- Detect suspicious processes, files, and network activities.
- Analyze threats using AI-based behavioral analysis.
- Validate threats using VirusTotal Intelligence.
- Calculate dynamic threat scores.
- Automatically mitigate high-risk threats.
- Provide centralized security monitoring.
- Secure access using JWT Authentication and RBAC.
- Generate security reports for auditing and analysis.

---

# ✨ Key Features
## 🔐 Role-Based Access Control (RBAC)

SentinelX implements Role-Based Access Control (RBAC) to ensure that users only have access to the features and actions permitted by their assigned role. This enhances system security, minimizes unauthorized access, and enforces the principle of least privilege.

Role	Permissions
Administrator	Full system access, user management, security policies, automated response configuration, report generation, and dashboard management.
Analyst	View alerts, analyze threats, monitor endpoints, generate reports, and perform incident investigation.
Viewer	Read-only access to the dashboard, alerts, and system status without modification privileges.
### RBAC Features
- JWT-Based Authentication
- Secure Password Hashing
- Role-Based Authorization
- Protected API Endpoints
- Session Timeout
- Secure Login & Logout
- Access Control for Critical Operations

---

## 🔍 Real-Time Endpoint Monitoring

- Process Monitoring
- File System Monitoring
- Network Connection Monitoring
- USB Device Monitoring
- Live System Status

---

## 🤖 AI-Based Threat Detection

- Machine Learning Threat Analysis
- Dynamic Threat Scoring
- Behavioral Detection
- Risk Classification
- Intelligent Threat Prioritization

---

## 🌐 Threat Intelligence

Integrated with:

- VirusTotal API

Used for:

- File Reputation Lookup
- Malware Validation
- SHA-256 Hash Verification
- Threat Intelligence Correlation

---

## ⚡ Automated Threat Response

- Process Termination
- Policy-Based Mitigation
- Threat Containment
- Incident Logging
- Alert Generation

---

## 🔐 Authentication & Access Control

- JWT Authentication
- Role-Based Access Control (Admin, Analyst, Viewer)
- Secure Password Hashing
- Protected REST APIs
- Session Timeout 
- Secure Login & Logout

---

## 📊 Interactive Dashboard

- Live Threat Score
- Security Alerts
- Running Processes
- File Monitoring Logs
- Network Monitoring
- Threat Analytics
- Security Policies
- System Health Monitoring

---

## 📄 Security Reporting 

- Threat Summary
- Incident History
- Risk Assessment
- PDF Report Generation
- Security Audit Reports

---

# 🏗️ System Architecture

```text
                React Frontend
                       │
               REST API (JSON)
                       │
               FastAPI Backend
                       │
        ┌──────────────────────────────┐
        │ Authentication (JWT + RBAC) │
        │ Endpoint Monitoring         │
        │ AI Threat Analysis          │
        │ Threat Intelligence         │
        │ Policy Engine               │
        │ Response Engine             │
        │ Report Generation           │
        │ SQLite Database             │
        └──────────────────────────────┘
```

---

# 🔄 System Workflow

```text
Endpoint Monitoring
(Process • File • Network • USB)
            │
            ▼
     Data Collection
            │
            ▼
 AI Threat Analysis Engine
 (Machine Learning)
            │
            ▼
 Threat Intelligence
 (VirusTotal API)
            │
            ▼
 Threat Score Generation
            │
            ▼
 Policy & Response Engine
      │             │
      ▼             ▼
 Alert Only   Auto Mitigation
      │             │
      └──────┬──────┘
             ▼
      Database Storage
             │
             ▼
 Real-Time Dashboard
             │
             ▼
 Security Reports
```

---

# 🚀 Innovative Features

- AI-Powered Threat Scoring
- Behavioral Threat Detection
- Real-Time Endpoint Monitoring
- Automated Threat Mitigation
- VirusTotal Threat Intelligence
- Interactive Security Dashboard
- Configurable Security Policies
- JWT Authentication & RBAC
- Automatic Session Timeout *(In Progress)*
- PDF Security Report Generation *(In Progress)*

---

# ⚙️ Technology Stack

| Category | Technology |
|-----------|------------|
| Frontend | React.js, Vite, Tailwind CSS |
| Backend | FastAPI, Python |
| AI | Scikit-learn |
| Monitoring | psutil, Watchdog, Scapy, Windows WMI |
| Threat Intelligence | VirusTotal API |
| Database | SQLite / PostgreSQL |
| Authentication | JWT, Passlib |
| Charts | Chart.js |
| HTTP Client | Axios |
| ORM | SQLAlchemy |
| Reporting | ReportLab |

---

# 📂 Project Structure

```text
SentinelX/
│
├── backend/
│   ├── app/
│   │   ├── api/
│   │   ├── auth/
│   │   ├── core/
│   │   ├── database/
│   │   ├── intelligence/
│   │   ├── monitoring/
│   │   ├── response/
│   │   ├── schemas/
│   │   └── services/
│   │
│   ├── main.py
│   └── requirements.txt
│
├── frontend/
│   ├── src/
│   │   ├── auth/
│   │   ├── components/
│   │   ├── pages/
│   │   ├── services/
│   │   └── App.jsx
│   │
│   ├── package.json
│   └── vite.config.js
│
├── watch_folder/
│
└── README.md
```

---

# 🛠 Installation

## Clone Repository

```bash
git clone https://github.com/<username>/SentinelX.git
cd SentinelX
```

---

## Backend Setup

```bash
cd backend

python -m venv .venv
```

Windows

```bash
.venv\Scripts\activate
```

Linux/macOS

```bash
source .venv/bin/activate
```

Install dependencies

```bash
pip install -r requirements.txt
```

Run Backend

```bash
uvicorn main:app --reload
```

Backend

```
http://localhost:8000
```

Swagger

```
http://localhost:8000/docs
```

---

## Frontend Setup

```bash
cd frontend

npm install

npm run dev
```

Frontend

```
http://localhost:5173
```

---

# 🔐 Authentication

Default Users

| Username | Password | Role |
|----------|----------|------|
| admin | admin123 | Admin |
| analyst | analyst123 | Analyst |
| viewer | viewer123 | Viewer |

---

# 📊 Dashboard Modules

- Live Threat Dashboard
- AI Threat Score
- Active Alerts
- Process Monitoring
- File Monitoring
- Network Monitoring
- USB Monitoring
- Security Policies
- Threat Analytics
- Security Reports *(Upcoming)*

---

# 🧪 Test Files

```text
watch_folder/

invoice.pdf.exe
encrypted.locked
test123.txt
hello.txt
```

---

# 🔮 Future Enhancements

- Deep Learning Threat Detection
- Browser Extension Monitoring
- Email Attachment Scanning
- SIEM Integration
- Cloud Deployment
- Linux & macOS Support
- Multi-Agent Architecture
- Predictive Threat Intelligence
- Automated PDF Reports
- Session Timeout & Audit Logs

---

# 👨‍💻 Team

Developed as part of the **OSF Hackathon**.

---

# 🙏 Acknowledgements

Special thanks to the open-source community behind:

- FastAPI
- React
- Vite
- Scikit-learn
- psutil
- Watchdog
- Scapy
- SQLAlchemy
- Chart.js
- Tailwind CSS
- VirusTotal

---

# 📌 Conclusion

**SentinelX EDR** demonstrates how Artificial Intelligence, behavioral analysis, threat intelligence, and automated response can be integrated into a modern Endpoint Detection and Response platform. By combining real-time monitoring, AI-driven threat scoring, configurable security policies, automated mitigation, and an interactive dashboard, SentinelX provides proactive endpoint protection while minimizing manual intervention. Its modular architecture and scalable design make it a strong foundation for enterprise-grade cybersecurity solutions and future enhancements.

---

## ⭐ If you found this project useful, consider giving it a Star!
