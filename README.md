# SentinelX 🛡️

An AI-powered Endpoint Detection and Response (EDR) agent MVP designed for rapid threat detection, explainable risk assessment, and autonomous security response.

---

## Architecture Overview

SentinelX consists of two main layers:
1. **Python Security Agent (Backend)**: Monitors local active processes, socket connections, USB drives, and file system audit events (using `psutil` and `watchdog`). It evaluates process threat indexes in real-time using a Random Forest classifier (`scikit-learn`) and takes automated actions (like process termination or file quarantine).
2. **Security Analyst Console (Frontend)**: A glassmorphic dark-mode dashboard built with React, Vite, and Tailwind CSS. It connects to the backend API to show real-time process statistics, connections map, alert alerts, and includes controls to simulate threats for live judging/demos.

---

## Installation & Setup

You will need **Python 3.8+** and **Node.js** installed on your system.

### 1. Launch the Backend Service

1. Open your terminal and navigate to the `backend` folder:
   ```bash
   cd backend
   ```
2. Create and activate a Python virtual environment (recommended):
   ```bash
   python -m venv venv
   # On Windows:
   .\venv\Scripts\activate
   # On Mac/Linux:
   source venv/bin/activate
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Start the FastAPI server using Uvicorn:
   ```bash
   python main.py
   ```
   The backend API will run on `http://127.0.0.1:8000`. You can inspect the Interactive Docs at `http://127.0.0.1:8000/docs`.

---

### 2. Launch the Analyst Console (Frontend)

1. Open a new terminal window and navigate to the `frontend` folder:
   ```bash
   cd frontend
   ```
2. Install Node packages:
   ```bash
   npm install
   ```
3. Launch the Vite dev server:
   ```bash
   npm run dev
   ```
4. Open your browser and navigate to `http://localhost:5173`.

---

## How to Run Live Demos (Hackathon Judging Scenarios)

Judges love interactive live demos. SentinelX has built-in simulation options to showcase capabilities in real-time.

### Scenario A: Cryptominer Detection & Auto-Response
1. On the dashboard header, turn the **Auto-Response Policy** toggle **ON**.
2. Set the **Live Simulation** option to **Cryptominer**.
3. **What happens**: 
   - A mock process `xmrig_miner.exe` is loaded into the Process Monitor.
   - The AI engine detects anomalous metrics (CPU: 92%, 14 Connections) and predicts a **Threat Score of 88.5%**.
   - Because 88.5% is above the 85.0% threshold and the Auto-Response policy is ON, SentinelX triggers an automated mitigation response.
   - You will see a `CRITICAL` alert appear on the dashboard log: *“AI engine triggered automatic response for xmrig_miner.exe...”*
   - SentinelX automatically issues a process kill request, terminating the threat.

### Scenario B: File System Monitoring & Extension Hijacking
1. Click the **Live Directory Audit** tab on the dashboard.
2. In your file explorer, navigate to the folder monitored by SentinelX (indicated in the Directory Audit view, defaults to the project workspace directory).
3. Create a blank file with a double extension, such as `report.pdf.exe` or `invoice.docx.exe`.
4. **What happens**:
   - The Python `watchdog` sensor detects the file creation.
   - SentinelX immediately registers a double-extension exploit attempt and issues a `CRITICAL` file security alert on your dashboard alerts list.

### Scenario C: Unknown USB Insertion Alert
1. Plug a standard USB storage drive into your PC.
2. **What happens**:
   - SentinelX polls drive states and identifies a new logical drive partition.
   - A warning alert triggers in the panel: *“New USB storage drive detected at [Drive Letter]”*.
   - The global USB status icon updates to highlight potential physical vectors.
