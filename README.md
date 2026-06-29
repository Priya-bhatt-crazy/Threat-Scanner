# 🛡️ Malicious Threat Scanner & Response System

> **An AI-Assisted Real-Time Endpoint Security Solution for Threat Detection, Monitoring, and Automated Response**

![Python](https://img.shields.io/badge/Python-3.11-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-Backend-green)
![React](https://img.shields.io/badge/React-Frontend-61DAFB)
![Vite](https://img.shields.io/badge/Vite-Build-purple)
![SQLite](https://img.shields.io/badge/SQLite-Database-blue)
![License](https://img.shields.io/badge/License-MIT-yellow)

---

## 📖 Overview

The **Malicious Threat Scanner & Response System** is an AI-assisted cybersecurity application developed for the **OSF Hackathon**. It provides real-time monitoring of endpoint activities, detects suspicious behavior using heuristic analysis, integrates with external threat intelligence, and enables automated response actions through an interactive web dashboard.

Unlike traditional antivirus software that primarily relies on signature-based detection, this system focuses on monitoring system behavior, identifying suspicious activities, and providing administrators with actionable security insights.

---

## 🎯 Objectives

* Monitor endpoint activities in real time.
* Detect suspicious processes and file activities.
* Analyze system behavior using heuristic detection techniques.
* Verify suspicious files through VirusTotal.
* Generate real-time alerts.
* Support automated threat response.
* Provide an intuitive security dashboard for administrators.

---

# ✨ Features

### 🔍 Real-Time Monitoring

* Running Process Monitoring
* File System Monitoring
* USB Device Monitoring
* CPU & Memory Usage Tracking
* Live System Status Monitoring

---

### 🛡️ Threat Detection

* Heuristic-based threat analysis
* Suspicious process identification
* Suspicious file detection
* Threat scoring
* Real-time alert generation

---

### 🌐 Threat Intelligence

Integrated with:

* VirusTotal API

Used for:

* File reputation lookup
* Malware verification
* Threat validation

---

### ⚡ Automated Response

The system supports automated mitigation actions such as:

* Process termination
* File quarantine
* Alert generation
* Incident logging

---

### 📊 Interactive Dashboard

The React dashboard provides:

* Live Alerts
* Running Processes
* File Monitoring Logs
* Network Information
* Threat Statistics
* System Performance
* Threat Charts
* Monitoring Settings

---

## 🏗️ System Architecture

```text
                React Frontend
                       │
             REST API (JSON)
                       │
                FastAPI Backend
                       │
 ┌───────────────────────────────────────┐
 │ Authentication                        │
 │ Monitoring Manager                    │
 │ ├── Process Monitor (psutil)          │
 │ ├── File Monitor (watchdog)           │
 │ └── USB Monitor                       │
 │                                       │
 │ Threat Detection Engine               │
 │ VirusTotal Integration                │
 │ Response Engine                       │
 │ SQLite Database                       │
 └───────────────────────────────────────┘
```

---

# ⚙️ Technology Stack

| Category            | Technology                |
| ------------------- | ------------------------- |
| Frontend            | React, Vite, Tailwind CSS |
| Backend             | FastAPI, Python           |
| Database            | SQLite, SQLAlchemy        |
| Monitoring          | psutil, watchdog          |
| Threat Intelligence | VirusTotal API            |
| HTTP Client         | Axios                     |
| Authentication      | JWT-based Authentication  |
| Charts              | Chart.js                  |

---

# 📂 Project Structure

```text
backend/
│
├── app/
│   ├── api/
│   ├── auth/
│   ├── core/
│   ├── database/
│   ├── detection/
│   ├── intelligence/
│   ├── monitoring/
│   ├── response/
│   ├── schemas/
│   └── services/
│
├── main.py
└── sentinelx.db

frontend/
│
├── src/
│   ├── auth/
│   ├── components/
│   ├── pages/
│   ├── services/
│   └── App.jsx
│
├── package.json
└── vite.config.js

watch_folder/
README.md
```

---

# 🔄 System Workflow

```text
System Starts
      │
      ▼
Monitoring Manager
      │
      ├──────────────┐
      │              │
      ▼              ▼
Process Monitor   File Monitor
      │              │
      ▼              ▼
Threat Detection Engine
      │
      ▼
VirusTotal Verification
      │
      ▼
Threat Classification
      │
      ▼
Alert Generation
      │
      ▼
SQLite Database
      │
      ▼
Dashboard Update
      │
      ▼
Response Actions
```

---

# 🛠️ Installation

## Clone Repository

```bash
git clone https://github.com/<your-username>/Threat-Scanner.git
cd Threat-Scanner
```

---

## Backend Setup

Create a virtual environment:

```bash
python -m venv venv
```

Activate it:

**Windows**

```bash
venv\Scripts\activate
```

**Linux/macOS**

```bash
source venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Start the backend:

```bash
uvicorn main:app --reload
```

Backend URL:

```text
http://localhost:8000
```

---

## Frontend Setup

Install dependencies:

```bash
npm install
```

Run the development server:

```bash
npm run dev
```

Frontend URL:

```text
http://localhost:5173
```

---

# 🔐 Authentication

The application includes user authentication to secure dashboard access.

* User Login
* Protected Routes
* JWT-based Authentication
* Secure API Access

---

# 📁 Monitoring Modules

## Process Monitoring

Monitors:

* Process Name
* Process ID
* CPU Usage
* Memory Usage

---

## File Monitoring

Detects:

* File Creation
* File Modification
* File Deletion

---

## USB Monitoring

Detects removable storage device events and forwards them to the monitoring subsystem.

---

# 🚨 Threat Detection Pipeline

```text
File / Process Event
        │
        ▼
Behavior Analysis
        │
        ▼
Threat Detection
        │
        ▼
VirusTotal Lookup
        │
        ▼
Threat Classification
        │
        ▼
Alert Generation
        │
        ▼
Response Execution
```

---

# 📊 Dashboard Components

* Dashboard Overview
* Live Alerts Panel
* Running Process Table
* File Logs
* Network Table
* Threat Charts
* System Statistics
* Settings Panel

---

# 🧪 Test Files

The project includes sample files to verify detection and monitoring functionality:

```text
watch_folder/
├── hello.txt
├── test123.txt
├── invoice.pdf.exe
└── encrypted.locked
```

These files help demonstrate monitoring behavior and detection logic during testing.

---

# 🔮 Future Enhancements

* Advanced Machine Learning Models
* Ransomware Detection
* Linux & macOS Support
* Additional Threat Intelligence Providers
* SIEM Integration
* Email Threat Scanning
* Cloud Deployment
* Enhanced Behavioral Analytics

---

# 👨‍💻 Team

Developed as part of the **OSF Hackathon**.

---

## ⭐ Acknowledgements

Special thanks to the open-source communities behind:

* FastAPI
* React
* Vite
* psutil
* watchdog
* SQLAlchemy
* VirusTotal

---

## 📌 Conclusion

The **Malicious Threat Scanner & Response System** demonstrates how real-time monitoring, behavioral analysis, and external threat intelligence can be combined to improve endpoint security. Built with a modular architecture using FastAPI and React, it provides a practical foundation for modern threat detection and automated incident response while remaining extensible for future enhancements.
